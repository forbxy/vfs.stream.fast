#include "CurlBuffer.h"
#include <algorithm>
#include <string>
#include <cctype>
#include <kodi/addon-instance/VFS.h> // for logging
#include <kodi/General.h>
#include <kodi/Network.h>
#include <mutex>
#include <thread>
#include <atomic>
#include <map>
#include <list>
#include <unordered_map>
#include <sstream>
#include <memory>

size_t CCurlBuffer::LRU_BLOCK_SIZE = 1 * 1024 * 1024;
size_t CCurlBuffer::LRU_TOTAL_SIZE = 100 * 1024 * 1024;
size_t CCurlBuffer::LRU_MAX_BLOCKS = CCurlBuffer::LRU_TOTAL_SIZE / CCurlBuffer::LRU_BLOCK_SIZE;

// -----------------------------------------------------------------------------------------
// 全局 LRU 块缓存 (Global LRU Block Cache)
// -----------------------------------------------------------------------------------------
// 替代原有的 Head/Tail/Middle 静态缓存，使用统一的 LRU 块缓存
// 块大小 = 1MB (与 GetChunkSize 一致)，总容量 100MB = 100 块
// 支持多文件并发: 使用 (url, block_num) 复合键，不同文件的块共存于同一 LRU
// 块数据使用 shared_ptr，允许多个线程在锁外安全持有数据引用

struct LRUBlockKey
{
    std::string url;
    int64_t block_num;

    bool operator==(const LRUBlockKey& o) const
    {
        return block_num == o.block_num && url == o.url;
    }
};

struct LRUBlockKeyHash
{
    size_t operator()(const LRUBlockKey& k) const
    {
        size_t h1 = std::hash<std::string>{}(k.url);
        size_t h2 = std::hash<int64_t>{}(k.block_num);
        return h1 ^ (h2 * 2654435761ULL); // Knuth multiplicative hash
    }
};

struct LRUBlockCache
{
    // LRU 链表: front = 最近使用, back = 最久未用
    std::list<LRUBlockKey> lru_order;

    // (url, block_num) -> { 在 lru_order 中的迭代器, 块数据(shared_ptr) }
    std::unordered_map<LRUBlockKey,
        std::pair<std::list<LRUBlockKey>::iterator, std::shared_ptr<std::vector<uint8_t>>>,
        LRUBlockKeyHash> blocks;

    // 查询块，命中则提升到 MRU 端，返回 shared_ptr (调用方可在锁外安全使用)
    std::shared_ptr<std::vector<uint8_t>> Get(const std::string& url, int64_t block_num)
    {
        LRUBlockKey key{url, block_num};
        auto it = blocks.find(key);
        if (it == blocks.end()) return nullptr;
        lru_order.splice(lru_order.begin(), lru_order, it->second.first);
        return it->second.second;
    }

    // 插入块 (自动驱逐最久未用的块)
    void Put(const std::string& url, int64_t block_num, const uint8_t* data, size_t size)
    {
        LRUBlockKey key{url, block_num};
        auto it = blocks.find(key);
        if (it != blocks.end())
        {
            it->second.second = std::make_shared<std::vector<uint8_t>>(data, data + size);
            lru_order.splice(lru_order.begin(), lru_order, it->second.first);
            return;
        }
        while (blocks.size() >= CCurlBuffer::LRU_MAX_BLOCKS && !lru_order.empty())
        {
            blocks.erase(lru_order.back());
            lru_order.pop_back();
        }
        lru_order.push_front(key);
        blocks[key] = { lru_order.begin(), std::make_shared<std::vector<uint8_t>>(data, data + size) };
    }

    void Clear()
    {
        lru_order.clear();
        blocks.clear();
    }
};

static LRUBlockCache g_lru_cache;
static std::mutex g_lru_cache_mutex;

void CCurlBuffer::UpdateLRUSettings(size_t block_size, size_t total_size)
{
    std::lock_guard<std::mutex> lock(g_lru_cache_mutex);
    if (LRU_BLOCK_SIZE != block_size) {
        // 块大小改变会导致现有 block_num 计算失效，所以必须清空
        g_lru_cache.Clear();
    }
    
    LRU_BLOCK_SIZE = block_size;
    LRU_TOTAL_SIZE = total_size;
    
    if (LRU_BLOCK_SIZE == 0) LRU_BLOCK_SIZE = 1 * 1024 * 1024; // 兜底
    LRU_MAX_BLOCKS = LRU_TOTAL_SIZE / LRU_BLOCK_SIZE;

    // 清理超出的块
    while (g_lru_cache.blocks.size() > LRU_MAX_BLOCKS && !g_lru_cache.lru_order.empty())
    {
        g_lru_cache.blocks.erase(g_lru_cache.lru_order.back());
        g_lru_cache.lru_order.pop_back();
    }
}

// -----------------------------------------------------------------------------------------
// 全局 Stat 缓存 (Metadata Cache)
// -----------------------------------------------------------------------------------------
struct StatCacheEntry
{
    int64_t size = -1;
    bool exists = false;
    bool support_range = true; // 默认假设支持，除非被动发现不支持
    time_t mod_time = 0;
    time_t access_time = 0;
    bool is_dir = false;
    time_t cached_at = 0; // 缓存写入时间

    static constexpr int TTL_SEC = 60; // 缓存有效期 1 分钟
    bool IsExpired() const { return (time(nullptr) - cached_at) > TTL_SEC; }
};

// Key: URL (normalized), Value: StatCacheEntry
static std::map<std::string, StatCacheEntry> g_stat_cache;
static std::mutex g_stat_cache_mutex;

// -----------------------------------------------------------------------------------------
// 全局 Redirect 缓存 (302 Cache)
// -----------------------------------------------------------------------------------------
// 缓存 302 跳转后的有效 URL，下次直接访问目标地址
// [Fix] 增加时间戳以支持过期 (1小时)
struct RedirectCacheEntry
{
    std::string target_url;
    time_t timestamp;
};

// Key: Original URL, Value: RedirectCacheEntry
static std::map<std::string, RedirectCacheEntry> g_redirect_cache;
static std::mutex g_redirect_cache_mutex;
// -----------------------------------------------------------------------------------------


// 调试回调：用于打印发送的请求头以及连接信息
static int DebugCallback(CURL *handle, curl_infotype type, char *data, size_t size, void *userptr)
{
    if (type == CURLINFO_HEADER_OUT) {
        std::string header(data, size);
        while (!header.empty() && (isspace((unsigned char)header.back()))) {
            header.pop_back();
        }
        if (!header.empty()) {
            kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [Req Header] >> %s", header.c_str());
        }
    }
    else if (type == CURLINFO_HEADER_IN) {
        std::string header(data, size);
        while (!header.empty() && (isspace((unsigned char)header.back()))) {
            header.pop_back();
        }
        if (!header.empty()) {
            kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [Resp Header] << %s", header.c_str());
        }
    }
    // 添加连接信息日志，验证 TCP 复用
    else if (type == CURLINFO_TEXT) {
        std::string text(data, size);
        // 过滤常见的连接信息关键字
        if (text.find("Connected to") != std::string::npos || 
            text.find("Re-using existing connection") != std::string::npos ||
            text.find("Connection #") != std::string::npos)
        {
            // 移除尾部换行
            while (!text.empty() && (isspace((unsigned char)text.back()))) {
                text.pop_back();
            }
            kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [Connection Info] %s", text.c_str());
        }
    }
    return 0;
}

// -----------------------------------------------------------------------------------------

static bool IsFatalError(CURLcode res)
{
    static const std::vector<CURLcode> fatal_errors = {
        CURLE_URL_MALFORMAT,
        CURLE_COULDNT_RESOLVE_HOST, // Error 6: DNS resolution failed
        CURLE_COULDNT_CONNECT,
        CURLE_SSL_CONNECT_ERROR, // Error 35: SSL handshake failed
        CURLE_GOT_NOTHING // Empty reply, usually means server closed connection immediately, retry rarely helps for HEAD
    };
    
    for (auto code : fatal_errors) {
        if (res == code) return true;
    }
    return false;
}

// -----------------------------------------------------------------------------------------
// Helper: Get User Agent mimicking Kodi's native behavior
// -----------------------------------------------------------------------------------------

static std::string GetUserAgent()
{
    // Use Kodi's API to get the exact native User-Agent string
    // This ensures we match 'Kodi/21.2 (Windows NT ...)' exactly
    return kodi::network::GetUserAgent();
}

// [New] 获取文件扩展名函数 (使用 libcurl URL API 解析)
std::string CCurlBuffer::GetFileExtensionFromUrl(const std::string& url)
{
    std::string extension = "unknown";
    CURLU *h = curl_url();
    if(!h) return extension;

    // 解析 URL
    CURLUcode rc = curl_url_set(h, CURLUPART_URL, url.c_str(), CURLU_NON_SUPPORT_SCHEME);
    if(!rc) {
        char *path = NULL;
        // 提取 Path 部分 (会自动去除 ?query 和 #fragment)
        rc = curl_url_get(h, CURLUPART_PATH, &path, 0);
        if(!rc && path) {
            std::string path_str(path);
            
            // 1. 获取最后一段文件名 (Find last slash)
            size_t last_slash = path_str.rfind('/');
            std::string filename = (last_slash == std::string::npos) ? path_str : path_str.substr(last_slash + 1);

            // 2. 查找文件名中的最后一个点
            size_t dot_pos = filename.rfind('.');
            if (dot_pos != std::string::npos && dot_pos + 1 < filename.length()) {
                extension = filename.substr(dot_pos + 1);
                // 转换为小写
                std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
            }
            curl_free(path);
        }
    }
    curl_url_cleanup(h);
    return extension;
}

// Replace dav:// with http:// and davs:// with https:// for curl compatibility
static std::string FixDavProtocol(const std::string& url)
{
    std::string fixed = url;
    if (fixed.rfind("dav://", 0) == 0)
        fixed.replace(0, 6, "http://");
    else if (fixed.rfind("davs://", 0) == 0)
        fixed.replace(0, 7, "https://");
    return fixed;
}

// -----------------------------------------------------------------------------------------
// Helper: Resolve Recursive Redirects
// -----------------------------------------------------------------------------------------

// -----------------------------------------------------------------------------------------
// CURL Handle Pool (reuse handles to keep TCP connections alive)
// -----------------------------------------------------------------------------------------
static std::vector<CURL*> g_curl_handle_pool;
static std::mutex g_curl_pool_mutex;

static CURL* GetCurlHandleFromPool()
{
    std::lock_guard<std::mutex> lock(g_curl_pool_mutex);
    if (!g_curl_handle_pool.empty())
    {
        CURL* handle = g_curl_handle_pool.back();
        g_curl_handle_pool.pop_back();
        return handle;
    }
    return curl_easy_init();
}

static void ReturnCurlHandleToPool(CURL* handle)
{
    if (!handle) return;
    std::lock_guard<std::mutex> lock(g_curl_pool_mutex);
    // Limit pool size to prevent infinite growth (though Kodi calls are serial usually)
    if (g_curl_handle_pool.size() < 5) 
    {
        curl_easy_reset(handle); // Reset before reusing
        g_curl_handle_pool.push_back(handle);
    }
    else
    {
        curl_easy_cleanup(handle);
    }
}

// [Fix] 增加 TTL 参数
static std::string ResolveRedirectUrl(const std::string& input_url, long ttl = 14400)
{
    std::string current = input_url;
    std::lock_guard<std::mutex> lock(g_redirect_cache_mutex);
    time_t now = time(NULL);

    for(int i=0; i<10; i++)
    {
        auto it = g_redirect_cache.find(current);
        if (it != g_redirect_cache.end())
        {
            // [Fix] 检查有效期 (默认 4小时)
            if (now - it->second.timestamp < ttl)
            {
                if (it->second.target_url != current)
                {
                    current = it->second.target_url;
                }
                else
                {
                    break;
                }
            }
            else
            {
                // 已过期，删除记录并停止递归解析，回退到当前的 URL (即过期的上级)
                // 这样下次 Curl 请求就会使用这个 URL，重新触发重定向逻辑并更新缓存
                // FIXME 可能会有多层下级过期的被保留，但影响不大
                g_redirect_cache.erase(it);
                break;
            }
        }
        else
        {
            break;
        }
    }
    return current;
}

// -----------------------------------------------------------------------------------------
// Helper: Update Redirect Cache from CURL effective URL
// -----------------------------------------------------------------------------------------
// [Fix] 增加 self 指针以更新 m_total_size 等
void CCurlBuffer::UpdateRedirectCacheFromCurl(CURL* curl, const std::string& original_url, const char* context_name, CCurlBuffer* self)
{
    char *eff_url = NULL;
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &eff_url);
    if (eff_url)
    {
        std::string effective_url_str(eff_url);
        
        // 只有当有效 URL 与请求的 URL 不同时才认为是跳转
        // 且不只是协议的区别 (http vs https)
        // 简单判断: 字符串不相等
        if (original_url != effective_url_str)
        {
             // 1. 更新全局跳转缓存: A -> B
             bool is_new_redirect = false;
             {
                 std::lock_guard<std::mutex> lock(g_redirect_cache_mutex);
                 
                 // [Fix] 检查是否已存在相同的跳转记录
                 auto it = g_redirect_cache.find(original_url);
                 if (it != g_redirect_cache.end() && it->second.target_url == effective_url_str)
                 {
                     return; 
                 }
                 else
                 {
                     // 不存在或目标改变，写入新记录
                     RedirectCacheEntry entry;
                     entry.target_url = effective_url_str;
                     entry.timestamp = time(NULL);
                     g_redirect_cache[original_url] = entry;
                     is_new_redirect = true;
                 }
             }
             
             if (is_new_redirect)
             {
                kodi::Log(ADDON_LOG_DEBUG, "FastVFS: %s 检测到跳转: %s -> %s (Added to Cache)", context_name, original_url.c_str(), effective_url_str.c_str());
             }

             // [New] 如果发生了跳转，尝试从最终响应中获取正确的文件大小
             if (self)
             {
                 int64_t new_size = 0;
                 struct curl_header *h = NULL;
                 
                 // 1. 尝试 Content-Range (Worker/DownloadRange 常用)
                 if (curl_easy_header(curl, "Content-Range", 0, CURLH_HEADER, -1, &h) == CURLHE_OK)
                 {
                     if (h && h->value) {
                         std::string cr(h->value);
                         auto pos = cr.find('/');
                         if (pos != std::string::npos) {
                             std::string total_str = cr.substr(pos + 1);
                             if (total_str != "*" && !total_str.empty()) {
                                 try { new_size = std::stoll(total_str); } catch(...) {}
                             }
                         }
                     }
                 }
                 
                 // 2. 如果没找到 Range，且是 200 OK (非 Partial)，尝试 Content-Length
                 if (new_size <= 0)
                 {
                     long response_code = 0;
                     curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
                     if (response_code == 200)
                     {
                         curl_off_t cl = -1;
                         if (curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &cl) == CURLE_OK && cl > 0)
                         {
                             new_size = (int64_t)cl;
                         }
                         // [Explicit] 如果确实拿不到长度 (例如 GZIP 且没 Content-Length)，显式设为 0
                         // 这样后续逻辑就会禁用静态缓存并使用保守 RingBuffer
                         else
                         {
                             new_size = 0; 
                             // kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Redirect 200 OK but no Content-Length found (likely GZIP/Chunked). Size=0");
                         }
                     }
                 }

                 // 更新大小 (如果此时我们不知道大小，或者大小不一致)
                 if (new_size > 0 && (self->m_total_size == 0 || self->m_total_size != new_size))
                 {
                     kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [%s] Redirect target provided new size: %lld (Old: %lld)", context_name, new_size, self->m_total_size);
                     self->m_total_size = new_size;
                 }
             }
        }
    }
}

CCurlBuffer::CCurlBuffer()
{
}

CCurlBuffer::~CCurlBuffer()
{
    Close();
}

void CCurlBuffer::Close()
{
    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: 调用 Close(), 当前逻辑位置=%lld, ForWrite=%d", m_logical_position, m_for_write);

    // ----- 写入模式清理 (Write Mode Cleanup) -----
    if (m_for_write)
    {
        // Signal EOF to UploadReadCallback so curl finishes the PUT request gracefully
        if (m_write_multi && m_write_curl && !m_write_error)
        {
            m_write_eof = true;
            m_write_paused = false;
            curl_easy_pause(m_write_curl, CURLPAUSE_CONT);

            // Drive multi until transfer completes
            int still_running = 1;
            while (still_running)
            {
                CURLMcode mc = curl_multi_perform(m_write_multi, &still_running);
                if (mc != CURLM_OK || !still_running)
                    break;
                curl_multi_poll(m_write_multi, NULL, 0, 1000, NULL);
            }

            // Check final HTTP status
            CURLMsg *msg;
            int msgs_left;
            while ((msg = curl_multi_info_read(m_write_multi, &msgs_left)))
            {
                if (msg->msg == CURLMSG_DONE)
                {
                    long code = 0;
                    curl_easy_getinfo(m_write_curl, CURLINFO_RESPONSE_CODE, &code);
                    if (msg->data.result != CURLE_OK || code >= 400)
                        kodi::Log(ADDON_LOG_ERROR, "FastVFS: OpenForWrite upload finished with error. HTTP=%ld, CurlCode=%d", code, msg->data.result);
                    else
                        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: OpenForWrite upload finished successfully. HTTP=%ld", code);
                }
            }
        }

        if (m_write_multi && m_write_curl)
        {
            curl_multi_remove_handle(m_write_multi, m_write_curl);
        }
        if (m_write_curl)
        {
            curl_easy_cleanup(m_write_curl);
            m_write_curl = nullptr;
        }
        if (m_write_multi)
        {
            curl_multi_cleanup(m_write_multi);
            m_write_multi = nullptr;
        }
        m_for_write = false;
        m_write_error = false;
        m_write_eof = false;
        m_write_buffer = nullptr;
        m_write_buffer_size = 0;
        m_write_buffer_pos = 0;
        m_write_paused = false;
        return;
    }

    // ----- 读取模式清理 (Read Mode Cleanup) -----
    // 1. 停止标志
    m_is_running = false;

    // 2. 唤醒所有可能在此等待的线程
    m_cv_reader.notify_all();
    m_cv_writer.notify_all();

    // 3. 等待工作线程结束
    if (m_worker_thread.joinable())
    {
        auto t0 = std::chrono::steady_clock::now();
        m_worker_thread.join();
        auto t1 = std::chrono::steady_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Worker join wait time: %lld ms", (long long)ms);
    }
}

// -----------------------------------------------------------------------------------------
// Helper: Detect Double Encoding
// -----------------------------------------------------------------------------------------
static bool IsLikelyDoubleEncoded(const std::string& url)
{
    // 特征: 出现超过一次 %25 且后面紧跟两个十六进制字符 (0-9, A-F)
    // 根据请求：检测二次编码时，要出现两次 %25[HEX][HEX] 才认为是二次编码
    int count = 0;
    size_t pos = 0;
    while ((pos = url.find("%25", pos)) != std::string::npos) {
        if (pos + 4 < url.length()) {
            char h1 = url[pos + 3];
            char h2 = url[pos + 4];
            if (isxdigit(h1) && isxdigit(h2)) {
                count++;
                if (count >= 2) return true;
            }
        }
        pos += 3; 
    }
    return false;
}

static void FixDoubleEncoding(std::string& url)
{
    // 安全修复: 仅当 %25 后面跟着两个 HEX 字符时，才将其替换为 %
    size_t pos = 0;
    while ((pos = url.find("%25", pos)) != std::string::npos) {
        bool is_double_encoded = false;
        if (pos + 4 < url.length()) {
            char h1 = url[pos + 3];
            char h2 = url[pos + 4];
            if (isxdigit(h1) && isxdigit(h2)) {
                is_double_encoded = true;
            }
        }

        if (is_double_encoded) {
            url.replace(pos, 3, "%");
            // 替换后变成了 %XX，我们需要跳过这个 % (pos+1) 继续检查后面
            // 但考虑到三重编码的情况 (%2525E9 -> %25E9)，我们其实应该保留 pos 不动或者只 +1
            // 这里为了简单安全，仅仅向前推进 1，防止死循环
            pos += 1; 
        } else {
            pos += 3;
        }
    }
}

bool CCurlBuffer::Stat(const kodi::addon::VFSUrl &url)
{
    m_file_url = url.GetURL();
    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: 调用 Stat(), URL=%s", m_file_url.c_str());

    // 每次 Stat 都重置这些由探测结果驱动的状态，避免沿用上一次实例状态
    m_support_range = false;
    m_is_directory = false;
    m_mod_time = 0;
    m_access_time = 0;
    
    // FIXME Url Cleaning: Remove Kodi options (after '|')
    // libcurl 不处理 '|' 及其后的选项，直接发给服务器会导致 400 或 插件崩溃
    size_t pipe_pos = m_file_url.find('|');
    if (pipe_pos != std::string::npos) {
        m_file_url = m_file_url.substr(0, pipe_pos);
    }
    
    // [Detection] 检测二次编码
    if (IsLikelyDoubleEncoded(m_file_url)) {
        kodi::Log(ADDON_LOG_WARNING, "FastVFS: [Warning] 检测到可能的二次编码 URL (Count >= 2)! (Contains %%25+Hex)");
        kodi::Log(ADDON_LOG_WARNING, "FastVFS: Original URL: %s", m_file_url.c_str());

        std::string fixed_url_preview = m_file_url;
        FixDoubleEncoding(fixed_url_preview);
        kodi::Log(ADDON_LOG_WARNING, "FastVFS: Fixed URL (Preview): %s", fixed_url_preview.c_str());
        
        // [Reserved] 自动修复代码保留但不执行
        if (false) FixDoubleEncoding(m_file_url);
    }

    m_username = url.GetUsername();
    m_password = url.GetPassword();

    // [Init] 初始化 Video 标志
    std::string ext = GetFileExtensionFromUrl(m_file_url);
    m_is_video = (ext == "mkv" || ext=="iso" || ext == "mp4" || ext == "avi" || ext == "mov" ||  
                  ext == "wmv" || ext == "flv" || ext == "webm" || ext == "m2ts" || 
                  ext == "ts" || ext == "bdmv" || ext == "ifo" || ext == "3gp" ||
                  ext == "rmvb" || ext =="rm" || ext == "vob" || ext == "mpg" || 
                  ext == "mpeg" );

    // ---------------------------------------------------------
    // 0. 检查全局 Stat 缓存
    // ---------------------------------------------------------
    {
        std::lock_guard<std::mutex> lock(g_stat_cache_mutex);
        auto it = g_stat_cache.find(m_file_url);
        if (it != g_stat_cache.end())
        {
            const StatCacheEntry& entry = it->second;
            if (entry.IsExpired())
            {
                kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Stat Cache EXPIRED: %s", m_file_url.c_str());
                g_stat_cache.erase(it);
            }
            else if (!entry.exists)
            {
                kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Stat Cache HIT (Not Found): %s", m_file_url.c_str());
                return false;
            }
            else
            {
                m_total_size = entry.size;
                m_support_range = entry.support_range;
                m_mod_time = entry.mod_time;
                m_access_time = entry.access_time;
                m_is_directory = entry.is_dir;
                kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Stat Cache HIT (Size: %lld): %s", m_total_size, m_file_url.c_str());
                return true;
            }
        }
    }

    // kodi::Log(ADDON_LOG_DEBUG, "FastVFS: 文件属性 (Stat) URL: %s", m_file_url.c_str());

    // 初始化通用变量
    bool success = false;
    int64_t final_size = 0;
    long response_code = 0;
    CURLcode res = CURLE_FAILED_INIT;

    CURL* curl = GetCurlHandleFromPool();
    if (!curl) return false;
    
    // 重置 Handle
    curl_easy_reset(curl);
    
    std::string target_url = m_file_url;
    if (m_is_video) {
        target_url = ResolveRedirectUrl(m_file_url, m_cfg_redirect_cache_ttl_sec);
    }

    // Determine WebDAV flag based on actual request target (after redirect resolution)
    bool isWebDav = (target_url.rfind("dav://", 0) == 0) || (target_url.rfind("davs://", 0) == 0);
    
    // Fix dav:// -> http:// for curl compatibility
    target_url = FixDavProtocol(target_url);

    // =========================================================================
    // 策略分支: WebDAV (PROPFIND) vs HTTP (HEAD)
    // =========================================================================
    
    struct curl_slist *headers = NULL;
    std::string resp_body;
    char errbuf[CURL_ERROR_SIZE];

    {
        curl_easy_reset(curl);
        errbuf[0] = 0;
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

        if (isWebDav)
        {
             // WebDAV Setup
             SetupStatWebDavOptions(curl, target_url, &headers);

             curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](void* buffer, size_t size, size_t nmemb, void* userp) -> size_t {
                std::string* s = (std::string*)userp;
                s->append((char*)buffer, size * nmemb);
                return size * nmemb;
             });
             curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp_body);
        }
        else
        {
             // HTTP HEAD Setup
             SetupStatHeadOptions(curl, target_url);
        }
        
        res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        
        // Clean headers
        if (headers) { curl_slist_free_all(headers); headers = NULL; }

        if (res != CURLE_OK)
        {
            kodi::Log(ADDON_LOG_ERROR, "FastVFS: Stat %s Error %d. Detail: %s", isWebDav ? "WebDAV" : "HTTP", res, errbuf);
            std::lock_guard<std::mutex> l(g_redirect_cache_mutex);
            g_redirect_cache.erase(m_file_url);
        }
    }

    if (isWebDav)
    {
        // --- Debug Log 插入 ---
        if (res != CURLE_OK || (response_code != 200 && response_code != 207))
        {
             kodi::Log(ADDON_LOG_ERROR, "FastVFS: Stat WebDAV Failed! Res=%d, Code=%ld", res, response_code);
             if (res != CURLE_OK) kodi::Log(ADDON_LOG_ERROR, "FastVFS: Curl Error: %s", curl_easy_strerror(res));
        }
        else
        {
             kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Stat WebDAV Success. Code=%ld, BodyLen=%zu", response_code, resp_body.size());
        }
        // ----------------------

        if (res == CURLE_OK && (response_code == 207 || response_code == 200))
        {
             // 假设 WebDAV 都支持 Range (通常如此)
             m_support_range = true; 
             
             // 解析 XML Body
             std::string body_lower = resp_body;
             std::transform(body_lower.begin(), body_lower.end(), body_lower.begin(), ::tolower);
             
             // 1. 检查是否为目录
             if (body_lower.find(":collection/>") != std::string::npos || body_lower.find("<collection/>") != std::string::npos) 
             {
                 m_is_directory = true;
                 final_size = 0;
             } else {
                 m_is_directory = false;
                 
                 // 2. 解析大小 getcontentlength
                 // 格式: <d:getcontentlength>12345</d:getcontentlength>
                 size_t pos = body_lower.find("getcontentlength>");
                 if (pos != std::string::npos) {
                     size_t start = pos + 17; // len("getcontentlength>")
                     size_t end = body_lower.find('<', start);
                     if (end != std::string::npos) {
                         std::string size_str = body_lower.substr(start, end - start);
                         try { final_size = std::stoll(size_str); } catch(...) {}
                     }
                 }
                 
                 // 3. 解析时间 getlastmodified
                 // 注意：这里需要去原始 resp_body 找，因为 curl_getdate 需要正确的大小写
                 pos = body_lower.find("getlastmodified>");
                 if (pos != std::string::npos) {
                     size_t start = pos + 16;
                     size_t end = body_lower.find('<', start);
                     if (end != std::string::npos) {
                         std::string date_str = resp_body.substr(start, end - start);
                         time_t t = curl_getdate(date_str.c_str(), NULL);
                         if (t > 0) m_mod_time = t;
                     }
                 }
             }
             
             // 既然 PROPFIND 成功，我们将 response_code 视为 200 以兼容后续 Cache 逻辑
             if (response_code == 207) response_code = 200;
        }
    }
    else
    {
        // -------------------------------------------------------------
        // HTTP/HTTPS 通用路径: 解析 HEAD 请求结果
        // -------------------------------------------------------------
        // 注意：请求已在上方统一循环中执行，这里仅处理 Response Header
        
        struct curl_header *h = NULL;
        int64_t content_length = -1;
        curl_off_t cl = -1;
        
        if (curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &cl) == CURLE_OK && cl >= 0)
            content_length = (int64_t)cl;

        // 获取 Last-Modified
        long file_time = -1;
        if (curl_easy_getinfo(curl, CURLINFO_FILETIME, &file_time) == CURLE_OK && file_time > 0)
            m_mod_time = (time_t)file_time;

        // 检查 Accept-Ranges
        bool explicit_accept_ranges = false;
        if (curl_easy_header(curl, "Accept-Ranges", 0, CURLH_HEADER, -1, &h) == CURLHE_OK)
        {
            if (h && h->value && std::string(h->value).find("bytes") != std::string::npos) 
                explicit_accept_ranges = true;
        }

        // 检查 Transfer-Encoding: chunked (仅供日志)
        bool is_chunked = false;
        if (curl_easy_header(curl, "Transfer-Encoding", 0, CURLH_HEADER, -1, &h) == CURLHE_OK)
        {
             if (h && h->value && std::string(h->value).find("chunked") != std::string::npos)
                is_chunked = true;
        }

        // 检查 Content-Range
        int64_t content_range_len = 0;
        if (curl_easy_header(curl, "Content-Range", 0, CURLH_HEADER, -1, &h) == CURLHE_OK)
        {
            // 格式: bytes 0-0/123456
            if (h && h->value)
            {
                std::string cr(h->value);
                auto pos = cr.find('/');
                if (pos != std::string::npos)
                {
                    std::string total_str = cr.substr(pos + 1);
                    if (total_str != "*" && !total_str.empty())
                    {
                        try {
                            content_range_len = std::stoll(total_str);
                        } catch(...) {}
                    }
                }
            }
        }

        // 尝试判断是否为目录
        bool apparent_directory = false;
        char *ct = NULL;
        if (curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ct) == CURLE_OK && ct) {
            std::string contentType(ct);
            std::transform(contentType.begin(), contentType.end(), contentType.begin(), ::tolower);
            if (contentType.find("httpd/unix-directory") != std::string::npos) {
                apparent_directory = true;
            }
        }
        
        if (m_file_url.back() == '/' || apparent_directory) {
            m_is_directory = true;
        } else {
            m_is_directory = false;
        }

        // 提前定义 fallback 变量并检查文件类型
        bool need_fallback = false;
        
        // 对 .bdmv, .IFO, .BDM 等蓝光结构及图片文件，不做 fallback
        // 这些通常确实是小文件 且大多是kodi在频繁的扫文件夹，如果使用get，会穿透webdav缓存，直接访问源服务器，导致账号被风控
        // FIXME 对于404的fallback是兼容emby-next-gen的无奈之举，需更加严谨的调查改进
        std::string check_ext = GetFileExtensionFromUrl(m_file_url); 
        bool is_sensitive_file = (check_ext == "bdmv" || check_ext == "ifo" || check_ext == "bdm" || 
                                check_ext == "jpg" || check_ext == "png" || check_ext == "tbn");

        if (res == CURLE_OK)
        {
            if (response_code == 206)
            {
                m_support_range = true;
                if (content_range_len > 0) final_size = content_range_len;
                else if (content_length > 0) final_size = content_length;
            }
            else if (response_code == 200)
            {
                if (explicit_accept_ranges) m_support_range = true;
                else m_support_range = false;

                if (content_length > 0)
                {
                    final_size = content_length;
                }
                else
                {
                    // [Important] 无法确定长度时，则默认给 0，依靠后续逻辑判断是否需要 fallback
                    final_size = 0;
                }
            }
            
             if (!is_sensitive_file)
             {
                // 一些服务器不支持 HEAD 请求，返回 4xx 错误码
                if (response_code >= 400 && response_code < 500)
                {
                    need_fallback = true;
                }
                //对于一些302跳转的服务器，head请求不执行跳转，我们必须使用GET请求来触发跳转获取正确的文件大小
                else if (response_code == 200 && content_length <= 0)
                {
                    need_fallback = true;
                }
             }
        }
        else if (res == CURLE_GOT_NOTHING && !is_sensitive_file)
        {
             // 服务器对 HEAD 返回空响应，直接判定为不支持 Range、长度未知
             kodi::Log(ADDON_LOG_WARNING, "FastVFS: Stat HEAD Error 52 (Empty Reply). 判定: 不支持 Range, 长度未知.");
             m_support_range = false;
             final_size = 0;
             response_code = 200; // 视为成功，让后续 Cache 逻辑正确处理
        }

        if (need_fallback)
        {
                    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Stat HEAD failed or Size=0 (%ld). Fallback to GET 0-1...", response_code);
                    
                    curl_easy_reset(curl);
                    SetupStatGetFallbackOptions(curl, target_url);

                    // [Safety] 必须防止服务器忽略 Range 直接发送全量文件 (返回 200 OK)
                    // 如果是这样，curl_easy_perform 会一直下载直到文件结束，导致卡死
                    // 我们设置一个回调，如果数据量超过阈值 (比如 10KB)，就强制断开
                    struct FallbackCtx {
                        size_t total_received = 0;
                    } fb_ctx;
                    
                    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &fb_ctx);
                    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](void* buffer, size_t size, size_t nmemb, void* userp) -> size_t {
                        FallbackCtx* ctx = (FallbackCtx*)userp;
                        size_t real_size = size * nmemb;
                        ctx->total_received += real_size;
                        
                        // 阈值设为 10KB (Range 0-1 理论只要 2 字节)
                        if (ctx->total_received > 10 * 1024) {
                             // 返回 0 会触发 CURLE_WRITE_ERROR 中断传输
                             return 0; 
                        }
                        return real_size; // 丢弃数据但告诉 libcurl 已消费
                    });

                    res = curl_easy_perform(curl);
                    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
                    
                    // [Safety] 如果是被我们主动中断的 (CURLE_WRITE_ERROR)，且是因为服务器发太多数据了
                    // 这通常意味着服务器是 200 OK (不支持 Range)，但也意味着 Header 已经收到了
                    if (res == CURLE_WRITE_ERROR && fb_ctx.total_received > 10 * 1024)
                    {
                        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Fallback GET aborted (Too much data). Server likely ignores Range.");
                        // 尝试继续使用已获取的 header 信息
                        res = CURLE_OK; 
                    }

                    if (res == CURLE_OK) 
                    {
                        if (response_code == 206) {
                            kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Fallback GET Success. Code=206");
                            
                            // 此时 Content-Range 是必须的
                            if (curl_easy_header(curl, "Content-Range", 0, CURLH_HEADER, -1, &h) == CURLHE_OK) {
                                if (h && h->value) {
                                    std::string cr(h->value);
                                    auto pos = cr.find('/');
                                    if (pos != std::string::npos) {
                                        try { final_size = std::stoll(cr.substr(pos + 1)); } catch(...) {}
                                    }
                                }
                            }
                            m_support_range = true; // 能 206 就是支持
                        }
                        // 处理 200 OK 的情况 (有些服务器不支持 Range，直接返 200 和 Content-Length)
                        // 如果文件非常大怎么办？
                        else if (response_code == 200) {
                            kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Fallback GET Success (No Range). Code=200");
                            
                            curl_off_t cl = -1;
                            if (curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &cl) == CURLE_OK && cl > 0)
                            {
                                final_size = (int64_t)cl;
                            }
                            // 如果是 GET 0-1 返回了 200 OK，说明不支持 Range，且返回的是完整文件
                            m_support_range = false; 
                        }
                    }
                }
        } // End of else (HTTP/HTTPS block)
    

    // ---------------------------------------------------------
    // Update Redirect Cache (如果发生了跳转)
    // ---------------------------------------------------------
    if (res == CURLE_OK)
    {
        UpdateRedirectCacheFromCurl(curl, m_file_url, "Stat", this);
    }

    // ---------------------------------------------------------
    // 3. 更新 Stat Cache (通用)
    // ---------------------------------------------------------
    {
        std::lock_guard<std::mutex> lock(g_stat_cache_mutex);
        StatCacheEntry entry;

        if (response_code == 200 || response_code == 206)
        {
            success = true;
            m_total_size = final_size;
            
            entry.exists = true;
            entry.size = final_size;
            entry.mod_time = m_mod_time;
            entry.access_time = 0; 
            entry.support_range = m_support_range;
            entry.is_dir = m_is_directory;
            entry.cached_at = time(nullptr);
            
             kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Stat Success (%s). Size: %lld, Range: %d, Time: %lld, IsDir: %d", 
                 isWebDav ? "WebDAV" : "HTTP", final_size, m_support_range, (int64_t)m_mod_time, m_is_directory);
             
             // 成功结果总是已缓存
             g_stat_cache[m_file_url] = entry;
        }
        else
        {
            // [Fix] 仅明确的 404/410 才缓存 "Not Found"
            // 不要缓存网络超时(28)、连接拒绝(7)或服务器内部错误(5xx)，以便下次重试
            if (res == CURLE_OK && (response_code == 404 || response_code == 410))
            {
               kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Stat Failed (404/410). Code=%ld (Cached as Not Found)", response_code);
               entry.exists = false;
               entry.cached_at = time(nullptr);
               g_stat_cache[m_file_url] = entry;
            }
            else if (res == CURLE_OK && (response_code >= 400 && response_code < 500))
            {
               kodi::Log(ADDON_LOG_WARNING, "FastVFS: Stat Failed. CurCode=%d, HTTP=%ld, URL=%s (Not Cached, allowing retry)", res, response_code, m_file_url.c_str());
            }
            else
            {
               kodi::Log(ADDON_LOG_ERROR, "FastVFS: Stat Error. CurCode=%d, HTTP=%ld, URL=%s (Not Cached, allowing retry)", res, response_code, m_file_url.c_str());
            }
            success = false;
        }
    }

    ReturnCurlHandleToPool(curl);
    return success;
}

bool CCurlBuffer::Open(const kodi::addon::VFSUrl &url)
{
    kodi::Log(ADDON_LOG_INFO, "FastVFS: 正在打开文件: %s", url.GetURL().c_str());

    // Stat() 内部会处理 URL 清理、双重编码检测、协议修复、auth 提取
    if (!Stat(url))
    {
        return false;
    }

    // -------------------------------------------------------------
    // 动态内存策略 (Dynamic Memory Policy)
    // -------------------------------------------------------------
    
    // 1. 如果文件长度未知 (0)，使用保守的 Buffer 大小 (10MB)
    if (m_total_size <= 0)
    {
        m_ring_buffer_size = 10 * 1024 * 1024; // 10MB Conservative Buffer
        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [Dynamic] 未知长度 (0) -> 循环缓冲区: %zu bytes (保守模式)", m_ring_buffer_size);
    }
    // 2. RingBuffer 大小: 若文件小于配置的 RingBuffer 大小，Buffer 仅分配文件大小
    else if (m_total_size < (int64_t)m_cfg_ring_size)
    {
        // 向上对齐到 64KB
        size_t aligned_size = (size_t)((m_total_size + 65535) / 65536) * 65536;
        m_ring_buffer_size = aligned_size;
        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [小文件优化] %lld bytes < RingSize(%zu) -> 循环缓冲区: %zu bytes", m_total_size, m_cfg_ring_size, m_ring_buffer_size);
    }
    else
    {
        m_ring_buffer_size = m_cfg_ring_size;
    }


    kodi::Log(ADDON_LOG_INFO, "FastVFS: 打开文件成功 (Open success), 大小: %lld. Buffer=%zu. URL: %s", m_total_size, m_ring_buffer_size, m_file_url.c_str());

    // 初始化基础状态
    m_logical_position = 0;
    // 重置运行状态确保安全
    m_is_running = false; 

    return true;
}

void CCurlBuffer::StartWorker()
{
    if (m_worker_thread.joinable() || m_is_running)
        return;

    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [Lazy Init] 分配 RingBuffer 并启动 Worker 线程...");

    if (ring_buffer.empty())
        ring_buffer.resize(m_ring_buffer_size);

    m_is_running = true;
    m_is_eof = false;
    m_has_error = false;
    
    // 重置缓冲区指针
    m_rb_bytes_available = 0;
    m_ring_buffer_head = 0;
    m_ring_buffer_tail = 0;
    
    // 如果之前发生过 Seek，这里会自动从 Seek 后的位置开始，实现快速响应
    m_download_position = m_logical_position; 
    
    m_worker_thread = std::thread(&CCurlBuffer::WorkerThread, this);

    std::stringstream ss;
    ss << m_worker_thread.get_id();
    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Worker Thread Started. TID: %s", ss.str().c_str());
}

// -----------------------------------------------------------------------------------------
// 独立的缓存下载逻辑
// -----------------------------------------------------------------------------------------
struct CacheContext
{
    std::vector<uint8_t>* buffer;
    size_t offset;
    size_t limit;
};

size_t CCurlBuffer::CacheWriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    CacheContext *ctx = (CacheContext *)userp;

    if (ctx->offset + realsize > ctx->limit)
    {
        // 防止溢出，虽然理论上 curl range 控制住了
        realsize = ctx->limit - ctx->offset;
    }

    if (realsize > 0)
    {
        memcpy(ctx->buffer->data() + ctx->offset, contents, realsize);
        ctx->offset += realsize;
    }
    return realsize;
}



// -----------------------------------------------------------------------------------------
// Helper: Extract Host from URL (used to detect cross-domain redirects)
// -----------------------------------------------------------------------------------------
static std::string ExtractHost(const std::string& url)
{
    size_t protocol_pos = url.find("://");
    if (protocol_pos == std::string::npos) return "";
    size_t start = protocol_pos + 3;
    
    // Check for user:pass@
    size_t at_pos = url.find('@', start);
    size_t slash_pos = url.find('/', start);
    
    // If @ exists and is before /, start after @
    if (at_pos != std::string::npos && (slash_pos == std::string::npos || at_pos < slash_pos))
    {
        start = at_pos + 1;
    }
    
    size_t end = url.find('/', start);
    if (end == std::string::npos) return url.substr(start);
    return url.substr(start, end - start);
}

bool CCurlBuffer::DownloadRange(CURL* curl, int64_t start, int64_t length, std::vector<uint8_t>& buffer)
{
    if (!curl) return false;

    int retries = 0;
    CURLcode res = CURLE_FAILED_INIT;
    long response_code = 0;
    CacheContext ctx;
    char errbuf[CURL_ERROR_SIZE];

    while (retries < m_net_max_retries)
    {
        // 复用 SetupCurlOptions 的部分逻辑，但需要手动设置 WriteFunction
        // 同样使用 ResolveRedirectUrl 确保预热请求也是最新的
        // [Retry] 每次重试前重置 handle 状态
        curl_easy_reset(curl);
        errbuf[0] = 0;
        
        // 设置错误信息缓冲区
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

        std::string target_url = m_file_url;
        if (m_is_video)
        {
            target_url = ResolveRedirectUrl(m_file_url, m_cfg_redirect_cache_ttl_sec);
        }
        target_url = FixDavProtocol(target_url);
    
        // Use new helper
        SetupDownloadRangeOptions(curl, target_url, start, length);

        if (retries == 0) // Reduce log spam
        {
            kodi::Log(ADDON_LOG_DEBUG, "FastVFS: DownloadRange 发送 Range: bytes=%lld-%lld (Expect %lld bytes)", 
                start, start + length - 1, length);
        }
        else
        {
             kodi::Log(ADDON_LOG_DEBUG, "FastVFS: DownloadRange Retry %d/%d. Range: %lld-%lld", 
                retries, m_net_max_retries, start, start + length - 1);
        }

        // 设置回调
        ctx.buffer = &buffer;
        ctx.offset = 0;
        ctx.limit = buffer.size(); // 确保安全
    
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CCurlBuffer::CacheWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);

        res = curl_easy_perform(curl);
        
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    
        if (res == CURLE_OK)
        {
            // ---------------------------------------------------------
            // Update Redirect Cache (如果发生了跳转)
            // ---------------------------------------------------------
            UpdateRedirectCacheFromCurl(curl, m_file_url, "DownloadRange", this); // will use this->m_total_size

            // 检查 HTTP Code
            if (response_code >= 200 && response_code < 300)
            {
                // [安全修正] 如果下载的数据少于预期 (Short Read)，必须调整 buffer 大小
                if (ctx.offset < buffer.size())
                {
                    kodi::Log(ADDON_LOG_WARNING, "FastVFS: DownloadRange Short Read. Check: %zu < %zu", ctx.offset, buffer.size());
                    buffer.resize(ctx.offset);
                }
                return true; // Success!
            }
        }
        
        // Error handling for Retry
        if (res == CURLE_OPERATION_TIMEDOUT)
        {
              kodi::Log(ADDON_LOG_WARNING, "FastVFS: DownloadRange Low Speed/Timeout. Retry... (%d/%d). Detail: %s", retries + 1, m_net_max_retries, errbuf);
        }
        else
        {
              kodi::Log(ADDON_LOG_ERROR, "FastVFS: DownloadRange 失败. Code=%d, HTTP=%ld. Retry (%d/%d). Detail: %s", res, response_code, retries + 1, m_net_max_retries, errbuf);
        }
        
        // [Fix] 无论是超时还是错误，都清除跳转缓存，确保重试时使用最新链接
        {
            std::lock_guard<std::mutex> lock(g_redirect_cache_mutex);
            g_redirect_cache.erase(m_file_url);
        }

        retries++;
        if (retries < m_net_max_retries)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }
    
    return false;
}

// -----------------------------------------------------------------------------------------
// 真正的工作函数：Worker Thread 下的 Progress Callback
// -----------------------------------------------------------------------------------------
static int WorkerProgressCallback(void *clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow)
{
    CCurlBuffer *self = (CCurlBuffer *)clientp;
    
    // 1. 检查是否完全停止
    if (self && !self->m_is_running) 
    {
        return 1; // Abort
    }
    
    // 2. 检查是否收到"瞬移"打断信号
    if (self && self->IsTransferAborted())
    {
        // 返回非零值中止传输，但不意味着线程结束，只是这次 easy_perform 结束
        return 1; 
    }

    return 0;
}

void CCurlBuffer::WorkerThread()
{
    CURL* curl = GetCurlHandleFromPool();
    if (!curl) return;
    
    int retries = 0;
    char errbuf[CURL_ERROR_SIZE];

    while (m_is_running)
    {
        // ---------------------------------------------------------
        // 1. 检查并执行重置 (Reset Phase) - 响应式处理
        // ---------------------------------------------------------
        if (m_trigger_reset)
        {
             kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Worker 响应瞬移信号 (Reset Triggered). Target: %lld", (int64_t)m_reset_target_pos);
             {
                 std::unique_lock<std::mutex> lock(m_ring_buffer_mutex);
                 // 彻底清空 RingBuffer，断臂求生
                 m_ring_buffer_head = 0;
                 m_ring_buffer_tail = 0; 
                 m_rb_bytes_available = 0;
                 
                 // 关键: 将下载指针瞬移到新目标
                 m_download_position = m_reset_target_pos.load();
                 
                 m_is_eof = false;
                 // 如果之前有错，Seek 是最好的恢复机会
                 m_has_error = false; 
                 retries = 0; 
             }
             // 清除信号
             m_trigger_reset = false;
             m_abort_transfer = false;
        }

        // ---------------------------------------------------------
        // 2. 检查 EOF 状态 (Idle/Wait Phase)
        // ---------------------------------------------------------
        if (m_download_position >= m_total_size && m_total_size > 0)
        {
            if (!m_is_eof) {
                m_is_eof = true;
                m_cv_reader.notify_all(); // 通知 Read 可以读剩下的了
            }
            
            // 挂起等待唤醒 (等待 Reset 信号或者退出指令)
            std::unique_lock<std::mutex> lock(m_ring_buffer_mutex);
            // 只有当 reset 被触发 (意味着有新活了) 或者要关闭时才醒来
            m_cv_writer.wait(lock, [this] { return m_trigger_reset || !m_is_running; });
            
            if (!m_is_running) break;
            continue; // 醒来后继续循环，自然会进入 Step 1 处理 Reset
        }

        // ---------------------------------------------------------
        // 3. 执行下载 (Download Phase)
        // ---------------------------------------------------------
        
        // 每次循环（重新发起请求前）重置 Handle 状态
        curl_easy_reset(curl);
        errbuf[0] = 0;
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

        std::string target_url = m_file_url;
        if (m_is_video) {
            target_url = ResolveRedirectUrl(m_file_url, m_cfg_redirect_cache_ttl_sec);
        }
        target_url = FixDavProtocol(target_url);

        SetupWorkerDownloadOptions(curl, target_url, m_download_position);
        
        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Worker 开始下载. Pos: %lld", m_download_position.load());

        CURLcode res = curl_easy_perform(curl);
        
        if (res != CURLE_OK)
        {
             kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Worker 下载结束 (Error/Aborted). Res: %d. Detail: %s", res, errbuf);
        }

        // ---------------------------------------------------------
        // Update Redirect Cache (对所有已建立连接的情况都更新，不仅限于 CURLE_OK)
        // ---------------------------------------------------------
        {
            long resp_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp_code);
            if (resp_code > 0)
            {
                UpdateRedirectCacheFromCurl(curl, m_file_url, "Worker", this);
            }
        }

        // 运行时动态纠偏 (CURLE_OK 后的冗余检查，Header 回调已提前处理)
        if (res == CURLE_OK && !m_support_range)
        {
            long response_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

            bool supports_range_now = (response_code == 206);
            if (!supports_range_now)
            {
                struct curl_header* h = NULL;
                if (curl_easy_header(curl, "Accept-Ranges", 0, CURLH_HEADER, -1, &h) == CURLHE_OK)
                {
                    if (h && h->value && std::string(h->value).find("bytes") != std::string::npos)
                        supports_range_now = true;
                }
            }

            if (supports_range_now)
            {
                m_support_range = true;
                kodi::Log(ADDON_LOG_INFO, "FastVFS: [Dynamic] Worker 检测到最终地址支持 Range，已重新启用 LRU/Range 模式");
            }
        }

        // ---------------------------------------------------------
        // 4. 结果处理
        // ---------------------------------------------------------
        
        // 如果是被我们自己的 Callback 打断的 (返回 1 -> CURLE_ABORTED_BY_CALLBACK)
        // 且我们的信号旗确实树起来了，说明这是预期的 "瞬移"
        if (res == CURLE_ABORTED_BY_CALLBACK && m_abort_transfer)
        {
             // 直接 Continue，让下一次循环的 Step 1 处理 Reset
             continue;
        }

        if (res == CURLE_OK)
        {
            // [Fix] 成功完成一次传输（或者正常EOF），应该清零重试计数器
            // 否则在不稳定的网络下，多次的小中断累积起来会导致误判为"彻底没救"
            retries = 0;

            // [Auto-Detect Total Size]
            // 如果初始 Stat 失败导致 m_total_size 为 0，而我们现在成功完成了一次下载，
            // 那么当前的 m_download_position 很可能就是真实的文件大小 (EOF)。
            // 我们需要更新 m_total_size，否则 Step 2 的 EOF 检查永远无法通过，导致无限发起 "Pos: End" 的 Range 请求 (Error 33)
            if (m_total_size == 0 && m_download_position > 0)
            {
                 // 既然 res==OK，说明服务器认为发完了。我们信任当前的下载位置为文件末尾。
                 m_total_size = m_download_position;
                 kodi::Log(ADDON_LOG_INFO, "FastVFS: [Dynamic] 运行时修正文件大小: 0 -> %lld (Based on EOF)", m_total_size);
            }

            // 正常结束，这通常意味着下载完了 (EOF)
            // 虽然我们在 Step 2 检查 EOF，但这里作为防御
            m_is_eof = true;
            m_cv_reader.notify_all();
        }
        else if (res == CURLE_WRITE_ERROR)
        {
            // Stopped by user logic in WriteCallback?
        }
        else
        {
             // [New] 针对低速/超时错误的专门处理
            if (res == CURLE_OPERATION_TIMEDOUT)
            {
                kodi::Log(ADDON_LOG_WARNING, "FastVFS: Worker Low Speed/Timeout. Retry... (%d/%d)", retries + 1, m_net_max_retries);
            }
            else
            {
                kodi::Log(ADDON_LOG_ERROR, "FastVFS: Curl 错误: %d. 重试 %d/%d", res, retries, m_net_max_retries);
            }

            // [New] 发生错误时和超时时都清除 302 缓存，确保重试时使用原始 URL
            // 这可以防止因为 CDN 链接过期 (403/410) 或 IP 变动导致的持续错误
            // 下一次 SetupCurlOptions 会重新解析，libcurl 会自动处理跳转并触发 UpdateRedirectCacheFromCurl 更新缓存
            {
                std::lock_guard<std::mutex> lock(g_redirect_cache_mutex);
                g_redirect_cache.erase(m_file_url);
            }

            // [优化] 如果连接断开但缓冲区数据充足，先消耗缓冲区，避免立即重连
            // 场景: 暂停很久 -> 服务器断连 -> Keepalive 发现报错 -> 此时 Buffer 可能是满的
            // 如果立即重连，会因为 Buffer 满进入 HandleWrite 等待，导致新的连接又 Idle 很久再次被断
            {
               std::unique_lock<std::mutex> lock(m_ring_buffer_mutex);
               // 阈值设定: 90% RingBuffer
               // 注意: 设置为 90% 意味着只有缓冲非常满时才暂停重连。如果只想保持基本播放，可以调低比例。
               size_t wait_threshold = (size_t)(m_ring_buffer_size * 0.9);
               
               if (m_rb_bytes_available > wait_threshold)
               {
                   kodi::Log(ADDON_LOG_DEBUG, "FastVFS: 连接断开但缓冲充足 (%zu > %zu). 暂停重连...", m_rb_bytes_available, wait_threshold);
                   
                   // 挂起 Worker，直到:
                   // 1. 缓冲区数据下降到阈值以下 (说明开始播放消耗了)
                   // 2. 收到 Reset 信号 (用户拖动进度条)
                   // 3. 插件停止
                   m_cv_writer.wait(lock, [this, wait_threshold] { 
                       return m_rb_bytes_available < wait_threshold || m_trigger_reset || !m_is_running; 
                   });
                   
                   if (m_trigger_reset) 
                       kodi::Log(ADDON_LOG_DEBUG, "FastVFS: 暂停期间收到 Reset 信号，立即重连...");
                   else if (m_is_running)
                       kodi::Log(ADDON_LOG_DEBUG, "FastVFS: 缓冲水位下降 (低于阈值)，恢复重连...");
               }
            }

            retries++;
            if (retries > m_net_max_retries)
            {
                m_has_error = true;
                m_cv_reader.notify_all();
                
                // 出错后挂起，等待 Seek 救活它
                std::unique_lock<std::mutex> lock(m_ring_buffer_mutex);
                m_cv_writer.wait(lock, [this] { return m_trigger_reset || !m_is_running; });
            }
            else
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            }
        }
    }
    
    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Worker 线程退出.");
    ReturnCurlHandleToPool(curl);
}

void CCurlBuffer::SetupBaseCurlOptions(CURL* curl, const std::string& target_url)
{
    // Common settings
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L); // Multithreading safety
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, NULL);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, NULL);
    
    curl_easy_setopt(curl, CURLOPT_USERAGENT, GetUserAgent().c_str());
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "identity");
    curl_easy_setopt(curl, CURLOPT_AUTOREFERER, 0L);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, DebugCallback);

    // URL & Auth
    curl_easy_setopt(curl, CURLOPT_URL, target_url.c_str());

    // Don't send credentials to a different host (e.g. CDN after redirect)
    bool should_send_auth = true;
    {
        std::string host_origin = ExtractHost(m_file_url);
        std::string host_target = ExtractHost(target_url);
        if (!host_origin.empty() && !host_target.empty() && host_origin != host_target)
        {
             should_send_auth = false;
        }
    }

    if (!m_username.empty() && should_send_auth)
    {
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERNAME, m_username.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD, m_password.c_str());
    }
    else
    {
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
    }

    // [Fix] Allow sending credentials to redirected hosts (necessary when redirecting from Proxy to NAS with auth in URL)
    // curl_easy_setopt(curl, CURLOPT_UNRESTRICTED_AUTH, 1L);

    // SSL & Redirects
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    // [Fix] Allow all redirect
    curl_easy_setopt(curl, CURLOPT_POSTREDIR, CURL_REDIR_POST_ALL); 

    // Network & Timeouts
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, m_net_connect_timeout_sec);
    
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 15L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, 5L);

    // Optimize TCP Window Strategy
    // Disable Nagle's algorithm for lower latency
    curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1L);
    // Increase buffer size to 256KB (default is 16KB, max was 512KB in old libcurl)
    // Helps TCP window scaling for high latency high throughput (4K Remux)
    curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 256L * 1024L);

    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, m_net_low_speed_time_sec);
}

void CCurlBuffer::SetupStatWebDavOptions(CURL* curl, const std::string& target_url, struct curl_slist** headers_out)
{
    SetupBaseCurlOptions(curl, target_url);

    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PROPFIND");
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L); // Need Body
    curl_easy_setopt(curl, CURLOPT_RANGE, NULL); 
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, m_net_read_timeout_sec);

    if (headers_out) {
        *headers_out = curl_slist_append(*headers_out, "Depth: 0");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, *headers_out);
    }
}

void CCurlBuffer::SetupStatHeadOptions(CURL* curl, const std::string& target_url)
{
    SetupBaseCurlOptions(curl, target_url);
    
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADER, 0L); // We read headers via api
    curl_easy_setopt(curl, CURLOPT_FILETIME, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, m_net_read_timeout_sec);
}

void CCurlBuffer::SetupStatGetFallbackOptions(CURL* curl, const std::string& target_url)
{
    SetupBaseCurlOptions(curl, target_url);

    curl_easy_setopt(curl, CURLOPT_RANGE, "0-1"); 
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, m_net_read_timeout_sec);
}

void CCurlBuffer::SetupDownloadRangeOptions(CURL* curl, const std::string& target_url, int64_t start, int64_t length)
{
    SetupBaseCurlOptions(curl, target_url);

    // Probe specific timeouts
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, m_net_range_total_timeout_sec);
    
    std::string range = std::to_string(start) + "-" + std::to_string(start + length - 1);
    curl_easy_setopt(curl, CURLOPT_RANGE, range.c_str());
}

void CCurlBuffer::SetupWorkerDownloadOptions(CURL* curl, const std::string& target_url, int64_t start)
{
    SetupBaseCurlOptions(curl, target_url);

    // [New] 使用 Worker 专用的低速时间参数覆盖 Base 设置
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, m_net_worker_low_speed_time_sec);

    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, WorkerProgressCallback);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, this);
    
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CCurlBuffer::WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, this);
    curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 1 * 1024 * 1024);

    if (m_support_range)
    {
        curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE, (curl_off_t)start);
    }
    else
    {
        // 不支持 Range 的流必须按顺序连续读取，不能带偏移续传
        curl_easy_setopt(curl, CURLOPT_RANGE, NULL);
        curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE, (curl_off_t)0);
    }
}

size_t CCurlBuffer::WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    CCurlBuffer *self = (CCurlBuffer *)userp;
    return self->HandleWrite(contents, size * nmemb);
}

size_t CCurlBuffer::HandleWrite(void *contents, size_t size)
{
    if (!m_is_running)
        return 0;

    std::unique_lock<std::mutex> lock(m_ring_buffer_mutex);

    // ---------------------------------------------------------
    // 常规写入环形缓冲区 (Ring Buffer Write Only)
    // ---------------------------------------------------------
    // 移除所有 Snooping 逻辑，我们现在只关心 Ring Buffer

    // 背压 (Backpressure): 如果缓冲区满了，阻塞等待。
    while (m_rb_bytes_available + size > m_ring_buffer_size)
    {
        // 如果收到重置信号，立即返回 0 触发 CURLE_WRITE_ERROR 中断传输
        if (m_abort_transfer || m_trigger_reset)
        {
             kodi::Log(ADDON_LOG_DEBUG, "FastVFS: HandleWrite Interrupted by Reset Signal (Pre-wait).");
             return 0;
        }

        // kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Buffer Full (avail=%zu, size=%zu). Waiting...", m_rb_bytes_available, size);
        
        // 挂起等待 (可能被 Read 唤醒以进行重置，或被 Read 消费数据后唤醒)
        m_cv_writer.wait(lock);
        
        if (!m_is_running)
            return 0;
            
        // 唤醒后再次检查重置信号
        if (m_abort_transfer || m_trigger_reset)
        {
             kodi::Log(ADDON_LOG_DEBUG, "FastVFS: HandleWrite Interrupted by Reset Signal (Post-wait).");
             return 0;
        }
    }

    size_t written = 0;
    while (written < size)
    {
        size_t space_at_end = m_ring_buffer_size - m_ring_buffer_head;
        size_t toWrite = std::min(size - written, space_at_end);

        memcpy(ring_buffer.data() + m_ring_buffer_head, (uint8_t *)contents + written, toWrite);

        m_ring_buffer_head = (m_ring_buffer_head + toWrite) % m_ring_buffer_size;
        written += toWrite;
    }

    m_rb_bytes_available += size;
    m_download_position += size;

    m_cv_reader.notify_one();

    return size;
}

ssize_t CCurlBuffer::Read(uint8_t *buffer, size_t size)
{
    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Read() 请求 %zu bytes (Pos: %lld)", size, m_logical_position);

    // [EOF Check]
    if (m_total_size > 0 && m_logical_position >= m_total_size)
    {
         kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Read() EOF Reached (Pos >= Total). Returning 0.");
         return 0;
    }

    size_t total_read = 0;

    while (total_read < size)
    {
        if (!m_support_range)
        {
            if (!m_worker_thread.joinable())
            {
                StartWorker();
            }

            std::unique_lock<std::mutex> rb_lock(m_ring_buffer_mutex);

            while (m_rb_bytes_available == 0)
            {
                if (m_is_eof)
                    return total_read;
                if (m_has_error)
                    return total_read > 0 ? (ssize_t)total_read : -1;
                if (!m_is_running)
                    return total_read > 0 ? (ssize_t)total_read : -1;

                if (m_cv_reader.wait_for(rb_lock, std::chrono::seconds(60)) == std::cv_status::timeout)
                {
                    kodi::Log(ADDON_LOG_ERROR, "FastVFS: 顺序流 Read 严重超时 (60s). 返回错误 (-1).");
                    return total_read > 0 ? (ssize_t)total_read : -1;
                }
            }

            size_t space_to_end = m_ring_buffer_size - m_ring_buffer_tail;
            size_t to_copy = std::min(size - total_read, std::min(m_rb_bytes_available, space_to_end));
            memcpy(buffer + total_read, ring_buffer.data() + m_ring_buffer_tail, to_copy);

            m_ring_buffer_tail = (m_ring_buffer_tail + to_copy) % m_ring_buffer_size;
            m_rb_bytes_available -= to_copy;
            total_read += to_copy;
            m_logical_position += to_copy;

            m_cv_writer.notify_one();
            continue;
        }

        int64_t current_pos = m_logical_position;

        // EOF 检查
        if (m_total_size > 0 && current_pos >= m_total_size)
            break;

        int64_t block_num = current_pos / LRU_BLOCK_SIZE;
        size_t block_offset = (size_t)(current_pos % LRU_BLOCK_SIZE);

        // ---------------------------------------------------------
        // 1. 检查 LRU 块缓存
        // ---------------------------------------------------------
        {
            std::shared_ptr<std::vector<uint8_t>> block_ptr;
            {
                std::lock_guard<std::mutex> lru_lock(g_lru_cache_mutex);
                block_ptr = g_lru_cache.Get(m_file_url, block_num);
            }
            // shared_ptr 允许在锁外安全使用数据，即使其他线程驱逐了该块
            if (block_ptr)
            {
                size_t block_valid_size = block_ptr->size();
                if (block_offset < block_valid_size)
                {
                    size_t avail = block_valid_size - block_offset;
                    size_t to_copy = std::min(size - total_read, avail);
                    memcpy(buffer + total_read, block_ptr->data() + block_offset, to_copy);
                    total_read += to_copy;
                    m_logical_position += to_copy;
                    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: LRU 命中 Block#%lld, Offset: %zu, Copy: %zu", block_num, block_offset, to_copy);
                    continue; // 处理下一块
                }
                // block_offset >= block_valid_size: 这是 EOF 处的部分块，且已经读过了
                break;
            }
        }

        // ---------------------------------------------------------
        // 2. LRU 未命中 - 小文件直接下载到 LRU (无需 Worker)
        // ---------------------------------------------------------
        if (m_total_size > 0 && m_total_size <= (int64_t)LRU_BLOCK_SIZE)
        {
            kodi::Log(ADDON_LOG_DEBUG, "FastVFS: 小文件优化 (%lld bytes <= LRU_BLOCK_SIZE %zu), 直接 DownloadRange 到 LRU", m_total_size, LRU_BLOCK_SIZE);
            std::vector<uint8_t> file_data((size_t)m_total_size);
            CURL* dl_curl = GetCurlHandleFromPool();
            bool ok = DownloadRange(dl_curl, 0, m_total_size, file_data);
            ReturnCurlHandleToPool(dl_curl);

            if (ok && !file_data.empty())
            {
                {
                    std::lock_guard<std::mutex> lru_lock(g_lru_cache_mutex);
                    g_lru_cache.Put(m_file_url, 0, file_data.data(), file_data.size());
                }
                // 从刚写入的数据直接拷贝到输出
                size_t avail = file_data.size() - block_offset;
                size_t to_copy = std::min(size - total_read, avail);
                memcpy(buffer + total_read, file_data.data() + block_offset, to_copy);
                total_read += to_copy;
                m_logical_position += to_copy;
                kodi::Log(ADDON_LOG_DEBUG, "FastVFS: 小文件直接下载成功, 写入 LRU Block#0 (%zu bytes), Read %zu bytes", file_data.size(), to_copy);
                continue;
            }
            else
            {
                kodi::Log(ADDON_LOG_WARNING, "FastVFS: 小文件 DownloadRange 失败, 回退到 Worker 模式");
            }
        }

        // ---------------------------------------------------------
        // 3. LRU 未命中 - 从 RingBuffer 获取数据填充 LRU
        // ---------------------------------------------------------

        // 延迟启动 Worker
        if (!m_worker_thread.joinable())
        {
            StartWorker();
        }

        // 计算目标块的绝对范围
        int64_t block_start = block_num * (int64_t)LRU_BLOCK_SIZE;
        int64_t block_end_ideal = block_start + (int64_t)LRU_BLOCK_SIZE;
        if (m_total_size > 0)
            block_end_ideal = std::min(block_end_ideal, m_total_size);

        std::unique_lock<std::mutex> rb_lock(m_ring_buffer_mutex);

        // 内循环: 等待 RingBuffer 中出现完整块数据
        bool block_populated = false;
        while (true)
        {
            int64_t buf_start = m_download_position - m_rb_bytes_available;
            int64_t buf_end = m_download_position;

            // 如果到了 EOF，调整块尾边界
            int64_t block_end = block_end_ideal;
            if (m_is_eof && m_download_position < block_end)
                block_end = m_download_position;
            // 如果 total_size 在运行中被动态修正
            if (m_total_size > 0 && block_end > m_total_size)
                block_end = m_total_size;

            size_t block_size = 0;
            if (block_end > block_start)
                block_size = (size_t)(block_end - block_start);

            // 检查 RingBuffer 是否覆盖了整个块
            if (block_size > 0 && block_start >= buf_start && block_end <= buf_end)
            {
                // ----- 从环形缓冲区提取块数据 -----
                std::vector<uint8_t> block_data(block_size);
                size_t offset_from_tail = (size_t)(block_start - buf_start);
                size_t read_ptr = (m_ring_buffer_tail + offset_from_tail) % m_ring_buffer_size;

                size_t copied = 0;
                while (copied < block_size)
                {
                    size_t space_to_end = m_ring_buffer_size - read_ptr;
                    size_t chunk = std::min(block_size - copied, space_to_end);
                    memcpy(block_data.data() + copied, ring_buffer.data() + read_ptr, chunk);
                    read_ptr = (read_ptr + chunk) % m_ring_buffer_size;
                    copied += chunk;
                }

                // ----- Lazy Pruning: 释放 RingBuffer 中已读过的旧数据 -----
                {
                    size_t bytes_to_drop = (size_t)(block_start - buf_start);
                    if (bytes_to_drop > m_rb_bytes_available)
                        bytes_to_drop = m_rb_bytes_available;
                    if (bytes_to_drop > 0)
                    {
                        m_ring_buffer_tail = (m_ring_buffer_tail + bytes_to_drop) % m_ring_buffer_size;
                        m_rb_bytes_available -= bytes_to_drop;
                        m_cv_writer.notify_one();
                    }
                }

                // 释放 RingBuffer 锁后写入 LRU (避免双锁)
                rb_lock.unlock();

                // ----- 写入 LRU 缓存 -----
                {
                    std::lock_guard<std::mutex> lru_lock(g_lru_cache_mutex);
                    g_lru_cache.Put(m_file_url, block_num, block_data.data(), block_size);
                }

                // ----- 拷贝到输出 -----
                if (block_offset < block_size)
                {
                    size_t avail = block_size - block_offset;
                    size_t to_copy = std::min(size - total_read, avail);
                    memcpy(buffer + total_read, block_data.data() + block_offset, to_copy);
                    total_read += to_copy;
                    m_logical_position += to_copy;
                }

                kodi::Log(ADDON_LOG_DEBUG, "FastVFS: RingBuffer -> LRU Block#%lld (%zu bytes). Read %zu bytes.", block_num, block_size, total_read);
                block_populated = true;
                break; // 跳出内循环，继续外循环处理下一块
            }

            // ----- RingBuffer 中没有目标块数据，需要等待或重置 -----

            // 检查是否需要重置 RingBuffer
            bool need_reset = false;
            int64_t plan_limit = buf_end + (int64_t)m_ring_buffer_size;

            if (block_start < buf_start)
            {
                kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Read 落后 (Lag). Block: %lld, BufStart: %lld. 触发瞬移.", block_start, buf_start);
                need_reset = true;
            }
            else if (block_start > plan_limit || (block_start - buf_end) > (16 * 1024 * 1024))
            {
                kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Read 超前 (Too Far/Gap > 16MB). Block: %lld, Limit: %lld, Gap: %lld. 触发瞬移.",
                    block_start, plan_limit, (int64_t)(block_start - buf_end));
                need_reset = true;
            }

            if (need_reset)
            {
                m_reset_target_pos = block_start;
                m_trigger_reset = true;
                m_abort_transfer = true;
                m_cv_writer.notify_all();
                m_has_error = false;
                m_is_eof = false;
            }

            // 错误状态 (非重置触发的)
            if (m_has_error && !need_reset)
            {
                return total_read > 0 ? (ssize_t)total_read : -1;
            }

            // EOF 且 RingBuffer 中无此块数据
            if (m_is_eof && block_start >= m_download_position)
            {
                return total_read;
            }

            // ----- 死锁预防: 主动释放 RingBuffer 中的旧数据为 Writer 腾出空间 -----
            {
                size_t bytes_to_drop = (size_t)(block_start - buf_start);
                if (bytes_to_drop > m_rb_bytes_available)
                    bytes_to_drop = m_rb_bytes_available;
                if (bytes_to_drop > 0)
                {
                    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Read 死锁预防 - 主动丢弃 %zu bytes. Avail Before: %zu", bytes_to_drop, m_rb_bytes_available);
                    m_ring_buffer_tail = (m_ring_buffer_tail + bytes_to_drop) % m_ring_buffer_size;
                    m_rb_bytes_available -= bytes_to_drop;
                    m_cv_writer.notify_all();
                }
            }

            // ----- 等待 Worker 填充数据 -----
            if (m_is_eof) return total_read;
            if (m_has_error) return total_read > 0 ? (ssize_t)total_read : -1;

            if (m_cv_reader.wait_for(rb_lock, std::chrono::seconds(60)) == std::cv_status::timeout)
            {
                kodi::Log(ADDON_LOG_ERROR, "FastVFS: Read 严重超时 (60s). 返回错误 (-1).");
                return -1;
            }

            if (m_has_error) return total_read > 0 ? (ssize_t)total_read : -1;
            if (m_is_eof && m_rb_bytes_available == 0) return total_read;
            if (!m_is_running) return -1;
            // 继续内循环，重新检查 RingBuffer
        }

        if (!block_populated)
            break; // 无法获取块数据，退出外循环
    }

    return total_read;
}

int64_t CCurlBuffer::Seek(int64_t position, int whence)
{
    // 针对不支持 Range (如 Emby 转码流) 的情况
    // 直接返回 -1 拒绝 Seek，告诉播放器不支持。
    // 例外：Seek 到 0 (通常是刚打开时) 需兼容
    if (!m_support_range)
    {
        if ((whence == SEEK_SET && position == 0) ||
            (whence == SEEK_CUR && position == 0))
        {
            // allowed: Seek(0) 和 IoControl(IOCTRL_SEEK_POSSIBLE) 兼容
        }
        else
        {
            // kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Seek rejected (Range not supported).");
            return -1;
        }
    }

    std::unique_lock<std::mutex> lock(m_ring_buffer_mutex);
    
    int64_t target_pos = 0;
    if (whence == SEEK_SET)
        target_pos = position;
    else if (whence == SEEK_CUR)
        target_pos = m_logical_position + position;
    else if (whence == SEEK_END)
        target_pos = m_total_size + position;

    if (target_pos < 0)
        target_pos = 0;
    
    // 只有当 m_total_size 有效 (>0) 时才做越界检查
    if (m_total_size > 0 && target_pos > m_total_size)
        target_pos = m_total_size;

    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Seek() 请求 %lld (模式: %d). 更新逻辑位置 (原: %lld).", target_pos, whence, m_logical_position);

    m_logical_position = target_pos; 

    // Lazy Seek: 这里不做任何网络操作，全部推迟到 Read() 中处理。
    return m_logical_position;
}

// -----------------------------------------------------------------------------------------
// 写入接口 (Write Interface)
// -----------------------------------------------------------------------------------------
// 参考 Kodi 原生 CurlFile 的 multi-interface 模式:
// - OpenForWrite: 设置 CURLOPT_UPLOAD, 使用 curl_multi 驱动
// - Write: 通过 READFUNCTION 回调向服务器传递数据
// - UploadReadCallback: curl 拉取数据的回调，数据发完后 PAUSE
// -----------------------------------------------------------------------------------------

size_t CCurlBuffer::UploadReadCallback(char *buffer, size_t size, size_t nitems, void *userp)
{
    CCurlBuffer *self = (CCurlBuffer *)userp;
    if (!self)
        return 0;

    // EOF signal: Close() sets m_write_buffer_size = 0 to indicate upload is done
    if (self->m_write_eof)
        return 0;

    if (self->m_write_buffer_pos >= self->m_write_buffer_size)
    {
        // 当前 Write() 的数据已全部发送，暂停传输等待下一次 Write()
        self->m_write_paused = true;
        return CURL_READFUNC_PAUSE;
    }

    size_t max_copy = size * nitems;
    size_t remaining = self->m_write_buffer_size - self->m_write_buffer_pos;
    size_t to_copy = std::min(max_copy, remaining);

    memcpy(buffer, self->m_write_buffer + self->m_write_buffer_pos, to_copy);
    self->m_write_buffer_pos += to_copy;

    return to_copy;
}

bool CCurlBuffer::OpenForWrite(const kodi::addon::VFSUrl &url, bool overWrite)
{
    m_file_url = url.GetURL();
    kodi::Log(ADDON_LOG_INFO, "FastVFS: OpenForWrite() URL=%s, OverWrite=%d", m_file_url.c_str(), overWrite);

    // URL 清理: 去掉 Kodi 的 '|' 参数
    size_t pipe_pos = m_file_url.find('|');
    if (pipe_pos != std::string::npos)
        m_file_url = m_file_url.substr(0, pipe_pos);

    m_username = url.GetUsername();
    m_password = url.GetPassword();

    // 检查文件是否已存在 (不覆写时拒绝)
    if (!overWrite)
    {
        CCurlBuffer probe;
        probe.m_net_connect_timeout_sec = m_net_connect_timeout_sec;
        probe.m_net_read_timeout_sec = m_net_read_timeout_sec;
        if (probe.Stat(url))
        {
            kodi::Log(ADDON_LOG_WARNING, "FastVFS: OpenForWrite 拒绝: 文件已存在且 overWrite=false");
            return false;
        }
    }

    // 初始化 curl multi 接口 (Kodi CurlFile 同样使用 multi 驱动上传)
    m_write_curl = curl_easy_init();
    if (!m_write_curl)
    {
        kodi::Log(ADDON_LOG_ERROR, "FastVFS: OpenForWrite curl_easy_init 失败");
        return false;
    }

    m_write_multi = curl_multi_init();
    if (!m_write_multi)
    {
        curl_easy_cleanup(m_write_curl);
        m_write_curl = nullptr;
        kodi::Log(ADDON_LOG_ERROR, "FastVFS: OpenForWrite curl_multi_init 失败");
        return false;
    }

    // 配置通用选项 (URL, auth, SSL, redirect, timeout 等)
    // 协议修复: dav:// -> http://, davs:// -> https:// (仅用于 curl 请求)
    SetupBaseCurlOptions(m_write_curl, FixDavProtocol(m_file_url));

    // 关键: 启用上传模式 (PUT)
    curl_easy_setopt(m_write_curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(m_write_curl, CURLOPT_READFUNCTION, UploadReadCallback);
    curl_easy_setopt(m_write_curl, CURLOPT_READDATA, this);

    // 将 easy handle 加入 multi
    curl_multi_add_handle(m_write_multi, m_write_curl);

    // 初始化写入状态
    m_for_write = true;
    m_write_error = false;
    m_logical_position = 0;
    m_write_buffer = nullptr;
    m_write_buffer_size = 0;
    m_write_buffer_pos = 0;
    m_write_paused = false;

    kodi::Log(ADDON_LOG_INFO, "FastVFS: OpenForWrite 成功. URL=%s", m_file_url.c_str());
    return true;
}

ssize_t CCurlBuffer::Write(const uint8_t *buffer, size_t size)
{
    if (!(m_for_write && m_write_multi && m_write_curl) || m_write_error)
        return -1;

    // 设置本次 Write 的数据源
    m_write_buffer = buffer;
    m_write_buffer_size = size;
    m_write_buffer_pos = 0;
    m_write_paused = false;

    // 恢复传输 (UploadReadCallback 暂停后，需要恢复才能继续)
    curl_easy_pause(m_write_curl, CURLPAUSE_CONT);

    CURLMcode result = CURLM_OK;
    m_write_still_running = 1;

    // 驱动 multi-interface 直到本次数据全部发送或传输被暂停
    while (m_write_still_running && !m_write_paused)
    {
        result = curl_multi_perform(m_write_multi, &m_write_still_running);

        if (!m_write_still_running)
            break;

        if (result != CURLM_OK)
        {
            long code = 0;
            curl_easy_getinfo(m_write_curl, CURLINFO_RESPONSE_CODE, &code);
            kodi::Log(ADDON_LOG_ERROR, "FastVFS: Write 失败. HTTP=%ld, Multi Error=%d", code, result);
            m_write_error = true;
            return -1;
        }

        // Wait for socket activity to avoid busy-spin
        if (!m_write_paused)
            curl_multi_poll(m_write_multi, NULL, 0, 1000, NULL);
    }

    // Check if transfer completed prematurely (server error etc.)
    if (!m_write_still_running && m_write_buffer_pos < m_write_buffer_size)
    {
        CURLMsg *msg;
        int msgs_left;
        while ((msg = curl_multi_info_read(m_write_multi, &msgs_left)))
        {
            if (msg->msg == CURLMSG_DONE && msg->data.result != CURLE_OK)
            {
                long code = 0;
                curl_easy_getinfo(m_write_curl, CURLINFO_RESPONSE_CODE, &code);
                kodi::Log(ADDON_LOG_ERROR, "FastVFS: Write transfer ended prematurely. HTTP=%ld, CurlCode=%d", code, msg->data.result);
                m_write_error = true;
                return -1;
            }
        }
    }

    ssize_t written = (ssize_t)m_write_buffer_pos;
    m_logical_position += written;
    return written;
}

int CCurlBuffer::Truncate(int64_t size)
{
    // HTTP/WebDAV 不支持 Truncate, 与 Kodi CurlFile 行为一致
    return -1;
}


