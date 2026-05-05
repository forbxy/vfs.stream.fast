#include "client.h"
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <thread>
#include <condition_variable>

// 导出标准 C 接口
ADDONCREATOR(CMyAddon)

// =========================================================================
// ISO 延迟关闭机制 (Deferred Close Cache)
// =========================================================================
// 蓝光 ISO 播放时 Kodi/libbluray 会对同一文件快速 Open/Close 数十次。
// 每次 Close 都销毁 Worker 线程，下次 Open 需要重新建连 (数百ms)。
// 延迟关闭: Close ISO 时不销毁 CCurlBuffer, 而是放入缓存并保持 Worker 运行。
// 下次 Open 同一 URL 时直接取出复用。后台清理线程精确到期后主动销毁。
// =========================================================================

static constexpr int CLOSE_DELAY_MS = 200; // 延迟关闭宽限期 (ms)

struct CachedSession {
    CCurlBuffer* buffer;
    std::chrono::steady_clock::time_point expire_at; // 到期时间点
};

static std::mutex g_cache_mutex;
static std::unordered_map<std::string, CachedSession> g_cache;
static std::condition_variable g_cache_cv;
static std::thread g_cleanup_thread;
static bool g_cleanup_running = false;

// 后台清理线程: 精确睡到最近到期时间，主动销毁过期会话
static void CleanupThreadFunc()
{
    std::unique_lock<std::mutex> lock(g_cache_mutex);
    while (g_cleanup_running)
    {
        if (g_cache.empty())
        {
            g_cache_cv.wait(lock); // 无缓存时零 CPU 等待
            continue;
        }

        // 找最早到期的会话
        auto earliest = std::min_element(g_cache.begin(), g_cache.end(),
            [](const auto& a, const auto& b) { return a.second.expire_at < b.second.expire_at; });

        // 精确睡到那个时间点 (中途被 notify 打断则重新计算)
        g_cache_cv.wait_until(lock, earliest->second.expire_at);

        // 清理所有已过期的
        auto now = std::chrono::steady_clock::now();
        for (auto it = g_cache.begin(); it != g_cache.end();)
        {
            if (now >= it->second.expire_at)
            {
                auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - it->second.expire_at + std::chrono::milliseconds(CLOSE_DELAY_MS)).count();
                kodi::Log(ADDON_LOG_DEBUG, "FastVFS: 延迟关闭到期 (%lldms), 销毁 Worker. URL: %s",
                           (long long)elapsed_ms, it->first.c_str());
                it->second.buffer->Close();
                delete it->second.buffer;
                it = g_cache.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }
}

// 启动清理线程 (首次使用时调用)
static void EnsureCleanupThread()
{
    if (!g_cleanup_running)
    {
        g_cleanup_running = true;
        g_cleanup_thread = std::thread(CleanupThreadFunc);
    }
}

// 销毁所有缓存会话并停止清理线程
static void ShutdownDeferredClose()
{
    {
        std::lock_guard<std::mutex> lock(g_cache_mutex);
        g_cleanup_running = false;
        // 销毁所有残留缓存
        for (auto& [url, session] : g_cache)
        {
            kodi::Log(ADDON_LOG_DEBUG, "FastVFS: 关闭残留延迟会话: %s", url.c_str());
            session.buffer->Close();
            delete session.buffer;
        }
        g_cache.clear();
    }
    g_cache_cv.notify_all();
    if (g_cleanup_thread.joinable())
        g_cleanup_thread.join();
}

// ---------------------------------------------------------------------------
// 实现
// ---------------------------------------------------------------------------

CClientVFS::CClientVFS(const kodi::addon::IInstanceInfo &instance)
    : kodi::addon::CInstanceVFS(instance)
{
    kodi::Log(ADDON_LOG_INFO, "Fast Stream VFS: Loaded");
}

CClientVFS::~CClientVFS()
{
    ShutdownDeferredClose();
    kodi::Log(ADDON_LOG_INFO, "Fast Stream VFS: Unloaded");
}

ADDON_STATUS CMyAddon::CreateInstance(const kodi::addon::IInstanceInfo &instance,
                                      KODI_ADDON_INSTANCE_HDL &hdl)
{
    if (instance.IsType(ADDON_INSTANCE_VFS))
    {
        kodi::Log(ADDON_LOG_INFO, "Creating Fast Stream VFS Instance");
        hdl = new CClientVFS(instance);
        return ADDON_STATUS_OK;
    }
    return ADDON_STATUS_UNKNOWN;
}

// 辅助函数：手动获取配置 (绕过头文件问题)
static int MyGetSettingInt(const std::string& settingName, int defaultValue)
{
    using namespace kodi::addon;
    int settingValue = defaultValue;
    if (CPrivateBase::m_interface && 
        CPrivateBase::m_interface->toKodi && 
        CPrivateBase::m_interface->toKodi->kodi_addon)
    {
        CPrivateBase::m_interface->toKodi->kodi_addon->get_setting_int(
          CPrivateBase::m_interface->toKodi->kodiBase, settingName.c_str(), &settingValue);
    }
    return settingValue;
}

kodi::addon::VFSFileHandle CClientVFS::Open(const kodi::addon::VFSUrl &url)
{
    // 核心入口：当 Kodi 要打开文件时调用
    std::string safeUrl = url.GetRedacted();
    std::string urlKey = url.GetURL();
    kodi::Log(ADDON_LOG_DEBUG, "Fast Stream VFS: Open %s", safeUrl.c_str());

    // ----- 延迟关闭复用: 若同一 URL 有已缓存的会话, 直接复用 -----
    {
        std::lock_guard<std::mutex> lock(g_cache_mutex);
        auto it = g_cache.find(urlKey);
        if (it != g_cache.end())
        {
            CCurlBuffer* file = it->second.buffer;
            auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                it->second.expire_at - std::chrono::steady_clock::now()).count();
            g_cache.erase(it);

            file->ResetForReuse();

            kodi::Log(ADDON_LOG_INFO, "FastVFS: ★ 复用延迟关闭会话 (剩余 %lldms). URL: %s",
                       (long long)remaining_ms, safeUrl.c_str());
            return (kodi::addon::VFSFileHandle)file;
        }
    }

    CCurlBuffer *file = new CCurlBuffer();

    // 读取设置
    file->m_cfg_ring_size = (size_t)MyGetSettingInt("ahead_size", 100) * 1024 * 1024;

    size_t lru_block_size = (size_t)MyGetSettingInt("lru_block_size", 1) * 1024 * 1024;
    size_t lru_total_size = (size_t)MyGetSettingInt("lru_total_size", 100) * 1024 * 1024;
    CCurlBuffer::UpdateLRUSettings(lru_block_size, lru_total_size);

    // [New] Fail Fast (Quick Timeout Reconnect)
    bool fail_fast = false;
    if (kodi::addon::CPrivateBase::m_interface && kodi::addon::CPrivateBase::m_interface->toKodi && kodi::addon::CPrivateBase::m_interface->toKodi->kodi_addon) {
        kodi::addon::CPrivateBase::m_interface->toKodi->kodi_addon->get_setting_bool(
          kodi::addon::CPrivateBase::m_interface->toKodi->kodiBase, "fail_fast", &fail_fast);
    }
    if (fail_fast) {
        file->m_net_connect_timeout_sec = 3;
        file->m_net_low_speed_time_sec = 3;
        file->m_net_worker_low_speed_time_sec = 10; // Worker 专用稍微宽松一些     
        file->m_net_read_timeout_sec = 5;
        
        // [New] Aggressive Range Timeout
        file->m_net_range_total_timeout_sec = 10;
    }

    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Config -> Ring = %zu MB, LRU = %zu MB (%zu blocks x %zu KB), FailFast=%d",
        file->m_cfg_ring_size >> 20,
        CCurlBuffer::LRU_TOTAL_SIZE >> 20, CCurlBuffer::LRU_MAX_BLOCKS, CCurlBuffer::LRU_BLOCK_SIZE >> 10,
        fail_fast);

    // [New] Use Kodi Proxy Settings
    bool use_kodi_proxy = false;
    if (kodi::addon::CPrivateBase::m_interface && kodi::addon::CPrivateBase::m_interface->toKodi && kodi::addon::CPrivateBase::m_interface->toKodi->kodi_addon) {
        kodi::addon::CPrivateBase::m_interface->toKodi->kodi_addon->get_setting_bool(
          kodi::addon::CPrivateBase::m_interface->toKodi->kodiBase, "use_kodi_proxy", &use_kodi_proxy);
    }
    file->m_use_kodi_proxy = use_kodi_proxy;
    if (use_kodi_proxy)
        file->LoadKodiProxySettings();

    // HTTP/2 Support
    bool enable_http2 = false;
    if (kodi::addon::CPrivateBase::m_interface && kodi::addon::CPrivateBase::m_interface->toKodi && kodi::addon::CPrivateBase::m_interface->toKodi->kodi_addon) {
        kodi::addon::CPrivateBase::m_interface->toKodi->kodi_addon->get_setting_bool(
          kodi::addon::CPrivateBase::m_interface->toKodi->kodiBase, "enable_http2", &enable_http2);
    }
    file->m_enable_http2 = enable_http2;

    // 初始化我们的加速器
    // 这里传入完整的 VFSUrl 对象，因为我们需要里面的 auth 信息
    if (file->Open(url))
    {
        return (kodi::addon::VFSFileHandle)file;
    }

    delete file;
    return nullptr; // 打开失败
}

ssize_t CClientVFS::Read(kodi::addon::VFSFileHandle context, uint8_t *buffer, size_t uiBufSize)
{
    CCurlBuffer *file = (CCurlBuffer *)context;
    if (!file)
        return -1;
    return file->Read(buffer, uiBufSize);
}

int64_t CClientVFS::Seek(kodi::addon::VFSFileHandle context, int64_t position, int whence)
{
    CCurlBuffer *file = (CCurlBuffer *)context;
    if (!file)
        return -1;
    return file->Seek(position, whence);
}

int64_t CClientVFS::GetPosition(kodi::addon::VFSFileHandle context)
{
    CCurlBuffer *file = (CCurlBuffer *)context;
    return file ? file->GetPosition() : 0;
}

int64_t CClientVFS::GetLength(kodi::addon::VFSFileHandle context)
{
    CCurlBuffer *file = (CCurlBuffer *)context;
    return file ? file->GetLength() : 0;
}

bool CClientVFS::Close(kodi::addon::VFSFileHandle context)
{
    CCurlBuffer *file = (CCurlBuffer *)context;
    if (!file)
        return false;

    // ----- ISO 延迟关闭: 保持 Worker 运行, 等待短时间内复用 -----
    if (file->IsIsoFile() && file->IsRangeSupported())
    {
        std::lock_guard<std::mutex> lock(g_cache_mutex);
        EnsureCleanupThread();

        std::string urlKey = file->GetOriginalUrl();

        // 如果同一 URL 已有缓存会话, 先销毁旧的
        auto it = g_cache.find(urlKey);
        if (it != g_cache.end())
        {
            kodi::Log(ADDON_LOG_WARNING, "FastVFS: 延迟关闭槽已被占用, 替换旧会话");
            it->second.buffer->Close();
            delete it->second.buffer;
            g_cache.erase(it);
        }

        auto expire_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(CLOSE_DELAY_MS);
        g_cache[urlKey] = {file, expire_at};
        g_cache_cv.notify_one(); // 唤醒清理线程重新计算到期时间

        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: ISO 延迟关闭 (宽限 %dms). URL: %s",
                   CLOSE_DELAY_MS, urlKey.c_str());
        return true;
    }

    file->Close();
    delete file;
    return true;
}

int CClientVFS::Stat(const kodi::addon::VFSUrl &url, kodi::vfs::FileStatus &buffer)
{
    // 必须实现获取文件大小，否则 Kodi 无法处理进度条
    CCurlBuffer tempFile;
    if (tempFile.Stat(url)) // 我们在 CCurlBuffer 实现一个仅仅 Head 请求的 Stat 方法
    {
        buffer.SetSize(tempFile.GetLength());
        buffer.SetIsDirectory(tempFile.IsDirectory());
        
        // 传递真实的修改时间
        time_t mod_time = tempFile.GetModificationTime();
        if (mod_time > 0)
            buffer.SetModificationTime(mod_time);
        else
            buffer.SetModificationTime(978310860); // fallback

        // 传递 Access Time (如果可用)
        time_t acc_time = tempFile.GetAccessTime();
        if (acc_time > 0)
            buffer.SetAccessTime(acc_time);

        return 0;
    }
    return -1;
}

bool CClientVFS::Exists(const kodi::addon::VFSUrl &url)
{
    kodi::vfs::FileStatus status;
    return Stat(url, status) == 0;
}

bool CClientVFS::Delete(const kodi::addon::VFSUrl& url)
{
    CCurlBuffer file;
    return file.DeleteUrl(url);
}

bool CClientVFS::Rename(const kodi::addon::VFSUrl& url, const kodi::addon::VFSUrl& url2)
{
    CCurlBuffer file;
    return file.RenameUrl(url, url2);
}

bool CClientVFS::DirectoryExists(const kodi::addon::VFSUrl& url)
{
    CCurlBuffer file;
    return file.DirectoryExistsUrl(url);
}

bool CClientVFS::RemoveDirectory(const kodi::addon::VFSUrl& url)
{
    CCurlBuffer file;
    return file.RemoveDirectoryUrl(url);
}

bool CClientVFS::CreateDirectory(const kodi::addon::VFSUrl& url)
{
    CCurlBuffer file;
    return file.CreateDirectoryUrl(url);
}

kodi::addon::VFSFileHandle CClientVFS::OpenForWrite(const kodi::addon::VFSUrl &url, bool overWrite)
{
    std::string safeUrl = url.GetRedacted();
    kodi::Log(ADDON_LOG_DEBUG, "Fast Stream VFS: OpenForWrite %s, OverWrite=%d", safeUrl.c_str(), overWrite);

    CCurlBuffer *file = new CCurlBuffer();

    // 复用读取模式的网络配置
    bool fail_fast = false;
    if (kodi::addon::CPrivateBase::m_interface && kodi::addon::CPrivateBase::m_interface->toKodi && kodi::addon::CPrivateBase::m_interface->toKodi->kodi_addon) {
        kodi::addon::CPrivateBase::m_interface->toKodi->kodi_addon->get_setting_bool(
          kodi::addon::CPrivateBase::m_interface->toKodi->kodiBase, "fail_fast", &fail_fast);
    }
    if (fail_fast) {
        file->m_net_connect_timeout_sec = 3;
        file->m_net_read_timeout_sec = 5;
    }

    if (file->OpenForWrite(url, overWrite))
    {
        return (kodi::addon::VFSFileHandle)file;
    }

    delete file;
    return nullptr;
}

ssize_t CClientVFS::Write(kodi::addon::VFSFileHandle context, const uint8_t *buffer, size_t uiBufSize)
{
    CCurlBuffer *file = (CCurlBuffer *)context;
    if (!file)
        return -1;
    return file->Write(buffer, uiBufSize);
}

int CClientVFS::Truncate(kodi::addon::VFSFileHandle context, int64_t size)
{
    CCurlBuffer *file = (CCurlBuffer *)context;
    if (!file)
        return -1;
    return file->Truncate(size);
}
