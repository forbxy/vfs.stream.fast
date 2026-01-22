#include "client.h"

// 导出标准 C 接口
ADDONCREATOR(CMyAddon)

// ---------------------------------------------------------------------------
// 实现
// ---------------------------------------------------------------------------

CClientVFS::CClientVFS(const kodi::addon::IInstanceInfo &instance)
    : kodi::addon::CInstanceVFS(instance)
{
    kodi::Log(ADDON_LOG_INFO, "Fast Stream VFS: Loaded");
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
    kodi::Log(ADDON_LOG_DEBUG, "Fast Stream VFS: Open %s", safeUrl.c_str());

    CCurlBuffer *file = new CCurlBuffer();

    // 读取设置
    // kodi::GetSettingInt 定义在 kodi namespace 下
    file->m_cfg_head_size = (size_t)MyGetSettingInt("head_size", 30) * 1024 * 1024;
    file->m_cfg_tail_size = (size_t)MyGetSettingInt("tail_size", 30) * 1024 * 1024;
    file->m_cfg_middle_size = (size_t)MyGetSettingInt("middle_size", 20) * 1024 * 1024;
    
    size_t ahead_size = (size_t)MyGetSettingInt("ahead_size", 100) * 1024 * 1024;
    file->m_cfg_history_size = (size_t)MyGetSettingInt("history_size", 10) * 1024 * 1024;
    
    file->m_cfg_ring_size = ahead_size + file->m_cfg_history_size;

    file->m_cfg_preload_thresh = (int64_t)MyGetSettingInt("preload_thresh", 10) * 1024 * 1024 * 1024;
    
    // [New] 读取 Only ISO Cache 选项 (默认 true)
    using namespace kodi::addon;
    bool cache_iso_only = true; 
    if (CPrivateBase::m_interface && CPrivateBase::m_interface->toKodi && CPrivateBase::m_interface->toKodi->kodi_addon) {
        CPrivateBase::m_interface->toKodi->kodi_addon->get_setting_bool(
          CPrivateBase::m_interface->toKodi->kodiBase, "cache_iso_only", &cache_iso_only);
    }
    file->m_cfg_cache_iso_only = cache_iso_only;

    // [New] 读取跳转缓存 TTL (默认 4 小时)
    int ttl_hours = MyGetSettingInt("redirect_cache_ttl", 4);
    if (ttl_hours > 0) {
        file->m_cfg_redirect_cache_ttl_sec = ttl_hours * 3600;
    }

    // [New] Fail Fast (Quick Timeout Reconnect)
    bool fail_fast = false;
    if (CPrivateBase::m_interface && CPrivateBase::m_interface->toKodi && CPrivateBase::m_interface->toKodi->kodi_addon) {
        CPrivateBase::m_interface->toKodi->kodi_addon->get_setting_bool(
          CPrivateBase::m_interface->toKodi->kodiBase, "fail_fast", &fail_fast);
    }
    if (fail_fast) {
        file->m_net_connect_timeout_sec = 3;
        file->m_net_low_speed_time_sec = 3;
        file->m_net_worker_low_speed_time_sec = 10; // Worker 专用稍微宽松一些     
        file->m_net_read_timeout_sec = 5;
        
        // [New] Aggressive Range Timeout
        file->m_net_range_total_timeout_sec = 10;
    }

    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Config -> H/T/M/R/His = %zu/%zu/%zu/%zu/%zu MB, Pre = %lld GB, ISOOnly=%d, FailFast=%d",
        file->m_cfg_head_size >> 20, file->m_cfg_tail_size >> 20, file->m_cfg_middle_size >> 20, 
        file->m_cfg_ring_size >> 20, file->m_cfg_history_size >> 20, file->m_cfg_preload_thresh >> 30,
        file->m_cfg_cache_iso_only, fail_fast);

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
    if (file)
    {
        file->Close();
        delete file; // 必须在这里释放内存
        return true;
    }
    return false;
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
