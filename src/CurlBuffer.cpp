#include "CurlBuffer.h"
#include <algorithm>
#include <string>
#include <cctype>
#include <kodi/addon-instance/VFS.h> // for logging
#include <kodi/General.h>
#include <mutex>
#include <thread>
#include <atomic>
#include <map>

// 定义一些常量
static const int MAX_RETRIES = 5;
static const int CONNECT_TIMEOUT = 10;
static const int READ_TIMEOUT = 30;

// -----------------------------------------------------------------------------------------
// 全局数据缓存 (Head & Tail)
// -----------------------------------------------------------------------------------------
// 单文件缓存策略：仅保留最后访问的文件缓存
struct GlobalDataCacheEntry
{
    std::string url;
    std::shared_ptr<std::vector<uint8_t>> head_buffer;
    std::shared_ptr<std::vector<uint8_t>> tail_buffer;
    size_t head_valid_length = 0;
    int64_t tail_valid_from = -1;

    // 热点缓存 (Middle/JIT Cache)
    std::shared_ptr<std::vector<uint8_t>> middle_buffer;
    int64_t middle_valid_from = -1;

    int64_t total_size = 0;
};

static GlobalDataCacheEntry g_data_cache;
static std::mutex g_data_cache_mutex;

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
    
    // 缓存校验信息 (ETag 等，暂略)
};

// Key: URL (normalized), Value: StatCacheEntry
static std::map<std::string, StatCacheEntry> g_stat_cache;
static std::mutex g_stat_cache_mutex;

// -----------------------------------------------------------------------------------------
// 全局 Redirect 缓存 (302 Cache)
// -----------------------------------------------------------------------------------------
// 缓存 302 跳转后的有效 URL，下次直接访问目标地址
// Key: Original URL, Value: Final Effective URL
static std::map<std::string, std::string> g_redirect_cache;
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
// Helper: Get User Agent mimicking Kodi's native behavior
// -----------------------------------------------------------------------------------------

static std::string GetUserAgent()
{
    struct kodi_version_t ver;
    kodi::KodiVersion(ver);
    
    std::string result = "Kodi/" + std::to_string(ver.major) + "." + std::to_string(ver.minor);

#if defined(_WIN32) || defined(_WIN64)
    result += " (Windows NT 10.0; Win64; x64)";
#elif defined(__APPLE__)
    result += " (Macintosh; Intel Mac OS X 10_15_7)";
#elif defined(__ANDROID__)
    result += " (Linux; Android 9.0)";
#elif defined(__linux__)
    result += " (X11; Linux x86_64)";
#else
    result += " (Unknown Platform)";
#endif

    result += " App_Bitness/64 Version/" + std::to_string(ver.major) + "." + std::to_string(ver.minor);
    return result;
}

// 简单的 Base64 编码实现 (避免依赖 kodi::tools 导致链接问题)
static std::string SimpleBase64Encode(const std::string &in) {
    std::string out;
    int val=0, valb=-6;
    for (unsigned char c : in) {
        val = (val<<8) + c;
        valb += 8;
        while (valb>=0) {
            out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(val>>valb)&0x3F]);
            valb-=6;
        }
    }
    if (valb>-6) out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[((val<<8)>>(valb+8))&0x3F]);
    while (out.size()%4) out.push_back('=');
    return out;
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

static std::string ResolveRedirectUrl(const std::string& input_url)
{
    std::string current = input_url;
    std::lock_guard<std::mutex> lock(g_redirect_cache_mutex);
    for(int i=0; i<10; i++)
    {
        auto it = g_redirect_cache.find(current);
        if (it != g_redirect_cache.end() && it->second != current)
        {
            current = it->second;
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
static void UpdateRedirectCacheFromCurl(CURL* curl, const std::string& original_url, const char* context_name)
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
             {
                 std::lock_guard<std::mutex> lock(g_redirect_cache_mutex);
                 g_redirect_cache[original_url] = effective_url_str;
             }
             
             kodi::Log(ADDON_LOG_DEBUG, "FastVFS: %s 检测到跳转: %s -> %s (Added to Cache)", context_name, original_url.c_str(), effective_url_str.c_str());
        }
    }
}

CCurlBuffer::CCurlBuffer()
{
    // 初始化复用的 Curl 对象
    // curl_handle = GetCurlHandleFromPool();
}

CCurlBuffer::~CCurlBuffer()
{
    Close();

    // if (curl_handle)
    // {
    //    ReturnCurlHandleToPool(curl_handle);
    //    curl_handle = nullptr;
    // }
}

void CCurlBuffer::Close()
{
    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: 调用 Close(), 当前逻辑位置=%lld", m_logical_position);
    // 1. 停止标志
    m_is_running = false;

    // 2. 唤醒所有可能在此等待的线程
    m_cv_reader.notify_all();
    m_cv_writer.notify_all();

    // 3. 等待工作线程结束
    if (m_worker_thread.joinable())
    {
        m_worker_thread.join();
    }
}

bool CCurlBuffer::Stat(const kodi::addon::VFSUrl &url)
{
    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: 调用 Stat(), URL=%s", url.GetURL().c_str());
    m_file_url = url.GetURL();
    m_username = url.GetUsername();
    m_password = url.GetPassword();


    

    // 协议修复: libcurl 不认识 dav://，只认识 http://
    if (m_file_url.rfind("dav://", 0) == 0)
        m_file_url.replace(0, 6, "http://");
    else if (m_file_url.rfind("davs://", 0) == 0)
        m_file_url.replace(0, 7, "https://");

    // 保存原始地址以用作缓存 Key
    std::string original_url = m_file_url;

    // ---------------------------------------------------------
    // 0. 检查全局 Stat 缓存
    // ---------------------------------------------------------
    {
        // 注意：这里使用 m_file_url (可能是 Redirect 后的) 作为 Key
        // 这意味着 Redirect Cache 必须先于 Stat Cache 检查
        std::lock_guard<std::mutex> lock(g_stat_cache_mutex);
        auto it = g_stat_cache.find(m_file_url);
        if (it != g_stat_cache.end())
        {
            const StatCacheEntry& entry = it->second;
            if (!entry.exists)
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
                // kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Stat Cache HIT (Size: %lld): %s", m_total_size, m_file_url.c_str());
                return true;
            }
        }
    }

    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: 文件属性 (Stat) URL: %s", m_file_url.c_str());

    // 初始化通用变量
    bool success = false;
    int64_t final_size = 0;
    long response_code = 0;
    CURLcode res = CURLE_FAILED_INIT;

    CURL* curl = GetCurlHandleFromPool();
    if (!curl) return false;
    
    // 重置 Handle
    curl_easy_reset(curl);
    bool isWebDav = (m_file_url.rfind("dav://", 0) == 0) || (m_file_url.rfind("davs://", 0) == 0);
    // =========================================================================
    // 策略分支: WebDAV (PROPFIND) vs HTTP (HEAD)
    // =========================================================================

    if (isWebDav)
    {
        // -------------------------------------------------------------
        // WebDAV 专用路径: 使用 PROPFIND Depth: 0 获取属性
        // -------------------------------------------------------------
        
        SetupCurlOptions(curl, false); // 非 HeadOnly，因为我们需要读取 Body (XML)
        
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PROPFIND");
        curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
        curl_easy_setopt(curl, CURLOPT_RANGE, NULL); 
        
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Depth: 0");
        // Authorization 已由 SetupCurlOptions 处理 (CURLOPT_USERNAME/PASSWORD)
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        std::string resp_body;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](void* buffer, size_t size, size_t nmemb, void* userp) -> size_t {
            std::string* s = (std::string*)userp;
            s->append((char*)buffer, size * nmemb);
            return size * nmemb;
        });
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp_body);
        
        res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        curl_slist_free_all(headers);

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
             if (body_lower.find(":collection/>") != std::string::npos || body_lower.find("<collection/>") != std::string::npos) {
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
        // HTTP/HTTPS 通用路径: 使用 HEAD 请求
        // -------------------------------------------------------------
        
        SetupCurlOptions(curl, true); // Head Only模式 (设置 CURLOPT_NOBODY)
        curl_easy_setopt(curl, CURLOPT_RANGE, "0-0");
        curl_easy_setopt(curl, CURLOPT_FILETIME, 1L); // 让 libcurl 处理时间

        res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

        // 使用 libcurl header API 解析
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

                final_size = content_length;
            }
        }
    }

    // ---------------------------------------------------------
    // Update Redirect Cache (如果发生了跳转)
    // ---------------------------------------------------------
    if (res == CURLE_OK)
    {
        UpdateRedirectCacheFromCurl(curl, m_file_url, "Stat");
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
            
             kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Stat Success (%s). Size: %lld, Range: %d, Time: %lld, IsDir: %d", 
                 isWebDav ? "WebDAV" : "HTTP", final_size, m_support_range, (int64_t)m_mod_time, m_is_directory);
        }
        else
        {
            if (response_code == 404 || response_code == 410)
            {
               kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Stat Failed (404/410). Code=%ld", response_code);
            }
            else
            {
               kodi::Log(ADDON_LOG_ERROR, "FastVFS: Stat Error. CurCode=%d, HTTP=%ld", res, response_code);
            }
            entry.exists = false;
            success = false;
        }
        g_stat_cache[m_file_url] = entry;
    }

    ReturnCurlHandleToPool(curl);
    return success;
}

bool CCurlBuffer::Open(const kodi::addon::VFSUrl &url)
{
    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Open() URL: %s", url.GetURL().c_str());
    m_file_url = url.GetURL();
    m_username = url.GetUsername();
    m_password = url.GetPassword();

    // 协议修复: 某些版本的 libcurl 只能处理 http/https，不认识 dav/davs
    if (m_file_url.rfind("dav://", 0) == 0)
        m_file_url.replace(0, 6, "http://");
    else if (m_file_url.rfind("davs://", 0) == 0)
        m_file_url.replace(0, 7, "https://");

    if (!Stat(url))
    {
        return false;
    }

    // -------------------------------------------------------------
    // 动态内存策略 (Dynamic Memory Policy)
    // -------------------------------------------------------------
    // 1. RingBuffer 大小: 若为小文件 (< 配置的 RingBuffer 大小)，Buffer 仅分配文件大小
    if (m_total_size > 0 && m_total_size < (int64_t)m_cfg_ring_size)
    {
        // 向上对齐到 64KB
        size_t aligned_size = (size_t)((m_total_size + 65535) / 65536) * 65536;
        m_ring_buffer_size = aligned_size;
        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [小文件优化] %lld bytes < RingSize(%zu) -> RingBuffer: %zu bytes", m_total_size, m_cfg_ring_size, m_ring_buffer_size);
    }
    else
    {
        m_ring_buffer_size = m_cfg_ring_size;
    }


    kodi::Log(ADDON_LOG_INFO, "FastVFS: 打开文件成功 (Open success), 大小: %lld. Buffer=%zu", m_total_size, m_ring_buffer_size);

    // 初始化基础状态
    m_logical_position = 0;
    m_head_valid_length = 0;
    m_tail_valid_from = -1;
    m_middle_valid_from = -1; // Reset Middle Cache state
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

bool CCurlBuffer::PreloadCaches()
{
    // 如果文件小于设定阈值 (默认 1GB)，跳过头尾预热，直接使用 Ring Buffer 流式读取
    if (m_total_size > 0 && m_total_size < m_cfg_preload_thresh)
    {
        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: 文件小于 %lld (设置阈值), 跳过头尾预热.", m_cfg_preload_thresh);
        return true;
    }

    // 0. 本地缓存检查 (Local Check) - 避免重复进入 global lock
    bool need_head = (m_head_valid_length == 0);
    bool need_tail = (m_total_size > (int64_t)(100 * 1024 * 1024)) && (m_tail_valid_from == -1);

    if (!need_head && !need_tail)
        return true;

    // Check Global Cache
    {
        std::lock_guard<std::mutex> lock(g_data_cache_mutex);
        if (g_data_cache.url == m_file_url && g_data_cache.total_size == m_total_size)
        {
            if (need_head && g_data_cache.head_valid_length > 0)
            {
                m_head_buffer = g_data_cache.head_buffer; // Zero-copy pointer assignment
                m_head_valid_length = g_data_cache.head_valid_length;
                need_head = false;
                kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [预热] 全局缓存命中: 头部.");
            }
            
            if (need_tail && g_data_cache.tail_valid_from != -1)
            {
                m_tail_buffer = g_data_cache.tail_buffer; // Zero-copy pointer assignment
                m_tail_valid_from = g_data_cache.tail_valid_from;
                need_tail = false;
                kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [预热] 全局缓存命中: 尾部.");
            }
        }
        else
        {
             // URL 不匹配，意味着切换了文件，清空旧缓存以释放内存
             g_data_cache = GlobalDataCacheEntry();
             g_data_cache.url = m_file_url;
        }
    }

    if (!need_head && !need_tail)
        return true;

    CURL* curl = GetCurlHandleFromPool();
    if (!curl) return false;

    // -------------------
    // 1. 下载头部 (Head)
    // -------------------
    if (need_head)
    {
        // 懒加载内存分配
        m_head_buffer = std::make_shared<std::vector<uint8_t>>();
        m_head_buffer->resize(m_cfg_head_size);

        // 确保清除上一次的状态
        curl_easy_reset(curl);

        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [预热] 开始下载头部... (0 - %zu)", m_head_buffer->size());
        if (DownloadRange(curl, 0, m_head_buffer->size(), *m_head_buffer))
        {
            m_head_valid_length = m_head_buffer->size();
            kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [预热] 头部下载完成.");
        }
        else
        {
            kodi::Log(ADDON_LOG_ERROR, "FastVFS: [预热] 头部下载失败.");
            ReturnCurlHandleToPool(curl);
            return false;
        }
    }

    // -------------------
    // 2. 下载尾部 (Tail)
    // -------------------
    bool ret = true;
    if (need_tail)
    {
        // 懒加载内存分配
        m_tail_buffer = std::make_shared<std::vector<uint8_t>>();
        m_tail_buffer->resize(m_cfg_tail_size);
        
        int64_t tail_start = m_total_size - m_tail_buffer->size();
        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [预热] 开始下载尾部... Start: %lld", tail_start);
        
        if (DownloadRange(curl, tail_start, m_tail_buffer->size(), *m_tail_buffer))
        {
            m_tail_valid_from = tail_start;
            kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [预热] 尾部下载完成. 覆盖范围: %lld - %lld (Total: %lld)", 
                tail_start, tail_start + (int64_t)m_tail_buffer->size(), m_total_size);

        }
        else
        {
            kodi::Log(ADDON_LOG_ERROR, "FastVFS: [预热] 尾部下载失败.");
            ret = false;
        }
    }
    
    ReturnCurlHandleToPool(curl);

    // -------------------
    // 3. 更新全局缓存
    // -------------------
    if (ret)
    {
        std::lock_guard<std::mutex> lock(g_data_cache_mutex);
        // 如果缓存 Key 还是我们开始时的 URL (即没人动过)，或者即使是最终跳转后的 URL (如果有人已经更新了)
        // 我们都应该更新内容。关键是我们要把最终有效的 m_file_url 存进去。
        if (g_data_cache.url == m_file_url)
        {
            g_data_cache.url = m_file_url; // 确保 Key 是最新的有效 URL (Redirected)
            g_data_cache.total_size = m_total_size;
            
            if (m_head_valid_length > 0)
            {
                g_data_cache.head_buffer = m_head_buffer;
                g_data_cache.head_valid_length = m_head_valid_length;
            }
            
            if (m_tail_valid_from != -1)
            {
                g_data_cache.tail_buffer = m_tail_buffer;
                g_data_cache.tail_valid_from = m_tail_valid_from;
            }
            kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [预热] 更新全局缓存成功. URL: %s", m_file_url.c_str());
        }
    }

    return ret;
}

bool CCurlBuffer::DownloadRange(CURL* curl, int64_t start, int64_t length, std::vector<uint8_t>& buffer)
{
    if (!curl) return false;

    // 复用 SetupCurlOptions 的部分逻辑，但需要手动设置 WriteFunction
    // 同样使用 ResolveRedirectUrl 确保预热请求也是最新的
    std::string target_url = ResolveRedirectUrl(m_file_url);
    curl_easy_setopt(curl, CURLOPT_URL, target_url.c_str());

    if (!m_username.empty())
    {
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERNAME, m_username.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD, m_password.c_str());
    }
    else
    {
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
    }
    
    // 设置 User-Agent (模仿 Kodi 原生 behavior)
    curl_easy_setopt(curl, CURLOPT_USERAGENT, GetUserAgent().c_str());
    // 模仿 Kodi 默认的 Accept-Encoding
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    // 模仿 Kodi 默认禁用 Auto Referer
    curl_easy_setopt(curl, CURLOPT_AUTOREFERER, 0L);

    // 启用调试回调以打印请求头 (排查 403 问题)
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, DebugCallback);
    
    // 基本设置
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L); // 预热超时短一点: 5秒连不上就算了
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);       // 增加一点超时时间
    
    // 设置 Range
    std::string range = std::to_string(start) + "-" + std::to_string(start + length - 1);
    curl_easy_setopt(curl, CURLOPT_RANGE, range.c_str());
    
    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: DownloadRange 发送 Range: bytes=%s (Expect %lld bytes)", range.c_str(), length);

    // 设置回调
    CacheContext ctx;
    ctx.buffer = &buffer;
    ctx.offset = 0;
    ctx.limit = buffer.size(); // 确保安全
    
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CCurlBuffer::CacheWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);

    CURLcode res = curl_easy_perform(curl);
    
    // 简单的错误处理
    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    
    if (res == CURLE_OK)
    {
        // ---------------------------------------------------------
        // Update Redirect Cache (如果发生了跳转)
        // ---------------------------------------------------------
        UpdateRedirectCacheFromCurl(curl, m_file_url, "DownloadRange");
    }

    if (res == CURLE_OK && (response_code >= 200 && response_code < 300))
    {
        // 只要 HTTP Code 正确，我们就认为 OK
        // [安全修正] 如果下载的数据少于预期 (Short Read)，必须调整 buffer 大小，
        // 否则 Read() 会读取到 buffer 末尾填充的 0，导致数据错误。
        if (ctx.offset < buffer.size())
        {
            kodi::Log(ADDON_LOG_WARNING, "FastVFS: DownloadRange Short Read. Check: %zu < %zu", ctx.offset, buffer.size());
            buffer.resize(ctx.offset);
        }
        return true;
    }
    
    kodi::Log(ADDON_LOG_ERROR, "FastVFS: DownloadRange 失败. Code=%d, HTTP=%ld", res, response_code);
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

        SetupCurlOptions(curl, false, m_download_position);
        
        // [关键] 启用基于信号的中断回调 (Signal-based Abort)
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
        curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, WorkerProgressCallback);
        curl_easy_setopt(curl, CURLOPT_XFERINFODATA, this);

        CURLcode res = curl_easy_perform(curl);

        // ---------------------------------------------------------
        // Update Redirect Cache
        // ---------------------------------------------------------
        if (res == CURLE_OK)
        {
            UpdateRedirectCacheFromCurl(curl, m_file_url, "Worker");
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
            kodi::Log(ADDON_LOG_ERROR, "FastVFS: Curl 错误: %d. 重试 %d/%d", res, retries, MAX_RETRIES);
            retries++;
            if (retries > MAX_RETRIES)
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
    
    ReturnCurlHandleToPool(curl);
}

// (Function ProgressCallback removed as it is superseded by WorkerProgressCallback)

void CCurlBuffer::SetupCurlOptions(CURL *curl, bool headOnly, int64_t startPos)
{
    // 移除全局的中断回调设置，避免影响 Stat/Preload (它们运行时 is_running=false)
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, NULL);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, NULL);
    
    // 设置 User-Agent (模仿 Kodi 原生 behavior)
    curl_easy_setopt(curl, CURLOPT_USERAGENT, GetUserAgent().c_str());

    // 模仿 Kodi 默认的 Accept-Encoding (允许压缩)
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    
    // 模仿 Kodi 默认禁用 Auto Referer (模拟 ffmpeg/browser 行为)
    curl_easy_setopt(curl, CURLOPT_AUTOREFERER, 0L);

    // 启用调试回调以打印请求头
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, DebugCallback);

    // B. 策略调整：下载阶段使用解析后的 URL
    // 在这里进行最终的 URL 解析，递归查找最新的有效地址
    std::string target_url = ResolveRedirectUrl(m_file_url);
    if (target_url != m_file_url) {
        // kodi::Log(ADDON_LOG_DEBUG, "FastVFS: URL Resolved: %s -> %s", m_file_url.c_str(), target_url.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_URL, target_url.c_str());

    // 只要有用户名，就默认使用 Basic Auth 并强制预先发送 Header
    // 这是为了满足 "直接构造 Basic Auth 头" 的需求，避免等待 401 质询
    if (!m_username.empty())
    {
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERNAME, m_username.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD, m_password.c_str());
    }
    else
    {
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
    }

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    if (headOnly)
    {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    }

    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIMEOUT);
    if (!headOnly)
    {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CCurlBuffer::WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, this);
        // 512k buffer size for curl internal
        curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 512 * 1024);

        curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE, (curl_off_t)startPos);
    }
    else
    {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
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
    // ---------------------------------------------------------
    // 0. 延迟预热检查 (Lazy Preload Check)
    // ---------------------------------------------------------
    // 每次 Read 前确保头尾缓存就绪 (如果是大文件且未初始化)
    // PreloadCaches 内部有状态检查，初始化过的会直接返回 true，开销极小
    // 注意: 这里不加锁 buffer_mutex，因为 PreloadCaches 是独立的连接操作，且只在初始化时写入
    // 另外，如果下载失败，返回 -1 通知 Kodi 错误
    if (!PreloadCaches())
    {
        kodi::Log(ADDON_LOG_ERROR, "FastVFS: Read 失败 - 预热缓存下载失败");
        return -1; // 返回 -1 表示读错误
    }

    std::unique_lock<std::mutex> lock(m_ring_buffer_mutex);
    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Read() 请求 %zu bytes (Pos: %lld)", size, m_logical_position);

    size_t total_read = 0;

    // ---------------------------------------------------------
    // 1. 优先检查静态缓存 (Static Caches) - 全命中策略
    // ---------------------------------------------------------
    // A. 头部缓存 (Head Cache)
    if (m_logical_position < (int64_t)m_head_valid_length)
    {
        // 计算实际需要提供的数据量 (处理 EOF 情况)
        size_t available_in_cache = (size_t)(m_head_valid_length - m_logical_position);
        size_t effective_request = size;
        
        // 如果文件很小，请求超出了总大小，我们将请求截断到 EOF，这样也算是"完全命中"
        if (m_total_size > 0 && m_logical_position + (int64_t)size > m_total_size)
        {
            effective_request = (size_t)(m_total_size - m_logical_position);
        }

        // 只有当缓存包含所有"有效"请求数据时才命中
        if (effective_request <= available_in_cache)
        {
            memcpy(buffer, m_head_buffer->data() + m_logical_position, effective_request);

            // [防御性编程] 处理 Short Read 的清零
            if (effective_request < size)
            {
                memset(buffer + effective_request, 0, size - effective_request);
            }

            kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Read 完全命中头部缓存. Pos: %lld, Req: %zu, Actual: %zu", m_logical_position, size, effective_request);
            m_logical_position += effective_request;
            return effective_request;
        }
    }
    // B. 尾部缓存 (Tail Cache)
    else if (m_total_size > 0 && m_tail_valid_from != -1 && m_logical_position >= m_tail_valid_from)
    {
        // int64_t tail_start = m_total_size - m_tail_buffer->size(); 
        // [Fix] 直接使用 m_tail_valid_from 作为基准，不再重新计算 tail_start
        // 因为如果 DownloadRange 发生了 Short Read 导致 buffer resize，重新计算会导致偏移错误
        {
            size_t offset = (size_t)(m_logical_position - m_tail_valid_from);
            
            // 只要 offset 在缓存范围内，我们就拥有直到 EOF 的所有数据。
            // 无论请求多大，只要它起始于此，这就是一次"完全命中"(对于文件内容而言)
            if (offset < m_tail_buffer->size())
            {
                size_t bytes_left_in_cache = m_tail_buffer->size() - offset;
                size_t to_copy = std::min(size, bytes_left_in_cache);

                memcpy(buffer, m_tail_buffer->data() + offset, to_copy);

                // [防御性编程] 如果读不满(到了EOF)，将剩余buffer清零，给个"干净的标记"
                if (to_copy < size)
                {
                    memset(buffer + to_copy, 0, size - to_copy);
                }

                kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Read 完全命中尾部缓存. Pos: %lld, Req: %zu, Actual: %zu%s", 
                    m_logical_position, size, to_copy, (to_copy < size ? " (EOF)" : ""));
                
                m_logical_position += to_copy;
                return to_copy;
            }
        }
    }

    // ---------------------------------------------------------
    // C. 如果头尾缓存都未命中，但kodi还是解析ISO，这就是最后的解药。
    // 中间热点缓存 (JIT Middle Cache) - 针对 ISO 菜单等随机读取优化
    // ---------------------------------------------------------
    
    // 如果 Worker 未运行，且确实需要使用热点缓存（非顺序读取，或者强制使用）
   if (!m_worker_thread.joinable())
    {
        // 尝试获取或创建 JIT Cache
        // CreateMiddleCache 内部会检查是否已存在有效的覆盖
        // 注意：原本只针对 Random Seek，现在根据指示，对于 !Worker 的情况直接依赖 JIT
        if (!CreateMiddleCache(m_logical_position))
        {
             kodi::Log(ADDON_LOG_ERROR, "FastVFS: CreateMiddleCache 下载失败，Read 终止.");
             return -1;
        }
    }

    // 尝试从 JIT 缓存读取 (CreateMiddleCache 成功后，这里一定会命中，除非 Cache 大小设计问题)
    if (m_middle_valid_from != -1 && m_logical_position >= m_middle_valid_from)
    {
        size_t offset = (size_t)(m_logical_position - m_middle_valid_from);
        if (offset < m_middle_buffer->size())
        {
            size_t bytes_left_in_cache = m_middle_buffer->size() - offset;
            size_t to_copy = std::min(size, bytes_left_in_cache);

            memcpy(buffer, m_middle_buffer->data() + offset, to_copy);
            
             // [防御性编程]
            if (to_copy < size)
                memset(buffer + to_copy, 0, size - to_copy);

            kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Read 命中JIT热点缓存. Pos: %lld, Req: %zu, Actual: %zu", m_logical_position, size, to_copy);
            m_logical_position += to_copy;

            // [JIT 接力机制]
            // 如果读取进度超过了热点缓存的一半，且 Worker 未启动，说明这可能是一个连续播放行为
            // 提前启动 Worker，实现无缝衔接 (虽然可能重复下载一小段热点缓存中剩余的数据，但保证了逻辑简单连续)
            // [优化] 只有当 JIT 缓存没有覆盖到文件末尾时才启动 Worker。如果 JIT 已经包含 EOF，直接用 JIT 读完即可。
            bool is_covered_to_eof = (m_total_size > 0 && (m_middle_valid_from + (int64_t)m_middle_buffer->size() >= m_total_size));

            if (!m_worker_thread.joinable() && !is_covered_to_eof && offset > m_middle_buffer->size() / 2)
            {
                 kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [JIT] 检测到连续读取 (Offset: %zu > Half), 提前启动 Worker 接力.", offset);
                 StartWorker();
            }

            return to_copy;
        }
    }

    // ---------------------------------------------------------
    // 延迟初始化 (Lazy Init)
    // ---------------------------------------------------------
    // 只有当缓存未命中，且确实需要从 RingBuffer 读取时才启动
    if (!m_worker_thread.joinable())
    {
        StartWorker();
    }

    // ---------------------------------------------------------
    // 2. 状态检查与决策 (Decision Making)
    // ---------------------------------------------------------
    
    // 检查 EOF (防止触发 Too Far 误报)
    if (m_total_size > 0 && m_logical_position >= m_total_size)
    {
        return total_read;
    }

    int64_t buffer_valid_start = m_download_position - m_rb_bytes_available; // 环形队列中数据的起始逻辑位置
    int64_t buffer_valid_end = m_download_position;                     // 环形队列中数据的结束逻辑位置
    int64_t plan_limit = m_download_position + (int64_t)m_ring_buffer_size;    // 视为"计划中"的最大范围

    bool need_reset = false;

    // 情况 A: 落后 (Lag) - 数据已被覆盖
    if (m_logical_position < buffer_valid_start)
    {
        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Read 落后 (Lag). Req: %lld, BufStart: %lld. 触发瞬移.", m_logical_position, buffer_valid_start);
        need_reset = true;
    }
    // 情况 B: 超前 (Too Far) - 超出计划范围 (定义为当前下载点 + 缓冲区大小)
    // 如果 Seek 到很远的位置，超过了这个范围，与其等待下载这一大段无用数据，不如直接重置
    else if (m_logical_position > plan_limit)
    {
        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Read 超前 (Too Far). Req: %lld, Limit: %lld. 触发瞬移.", m_logical_position, plan_limit);
        need_reset = true;
    }

    if (need_reset)
    {
        // 1. 设置目标
        m_reset_target_pos = m_logical_position;
        // 2. 举旗
        m_trigger_reset = true;
        m_abort_transfer = true; // 打断 Worker!
        // 3. 唤醒可能的睡眠 Worker
        m_cv_writer.notify_all(); 
        
        // 4. 清除错误标志，让 Read 循环继续并进入 wait
        m_has_error = false;
        m_is_eof = false; 
        
        // 注意：这里不需要 unlock/join。我们持有锁进入下方的 m_cv_reader.wait，释放锁后 Worker 会接管并重置。
    }

    // 只有在确定不触发重置的情况下，如果处于错误状态，才返回错误
    // 这样允许通过 Seek (导致 Lag/TooFar -> Reset) 来从错误中恢复
    if (m_has_error && !need_reset)
        return -1;

    // ---------------------------------------------------------
    // 3. 对齐队列头 (Align Ring Buffer Tail/Read Ptr)
    // ---------------------------------------------------------
    // 如果逻辑位置在现有数据中间，或者在"计划"中（意味着我们需要跳过当前队列头部的一些旧数据）
    // 我们必须丢弃 m_ring_buffer_tail 之前直到 m_logical_position 的数据
    // ---------------------------------------------------------
    // 3. RingBuffer 读取 (支持保留历史数据)
    // ---------------------------------------------------------

    while (total_read < size)
    {
        // 计算 Buffer 的绝对范围 (Snapshot of current state)
        int64_t buf_start = m_download_position - m_rb_bytes_available;
        int64_t buf_end = m_download_position;

        // [CRITICAL FIX] 检查 Lag (Backward Jump) 情况
        // 如果逻辑位置在缓冲区开始之前，说明我们也需要等待重置完成
        // 否则 avail_in_buffer 会计算出巨大的正数(因为减去更小的数)，导致 offset 下溢
        int64_t avail_in_buffer = 0;
        
        if (m_logical_position < buf_start) 
        {
            // Lag: We are behind. No data available.
            avail_in_buffer = 0;
        }
        else
        {
            // Normal or Too Far (Wait)
            avail_in_buffer = buf_end - m_logical_position;
        }

        if (avail_in_buffer <= 0)
        {
            // 数据不够，需要等待
            if (m_is_eof) return total_read; // 已经读到文件末尾
            if (m_has_error) return -1;
            
            // kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Read Waiting... (Pos: %lld, BufStart: %lld, BufEnd: %lld)", m_logical_position, buf_start, buf_end);

            m_cv_reader.wait(lock);
            
            // 唤醒后重新检查状态
            if (!m_is_running) return -1; // 发生重连或停止
            continue;
        }

        size_t current_need = size - total_read;
        size_t to_read = std::min(current_need, (size_t)avail_in_buffer);

        // 计算读取起始指针
        // m_logical_position 一定 >= buf_start (否则上面已经进入 wait)
        size_t offset_from_tail = (size_t)(m_logical_position - buf_start);
        size_t read_ptr = (m_ring_buffer_tail + offset_from_tail) % m_ring_buffer_size;

        // 执行拷贝 (处理 Ring Wrap)
        size_t copied = 0;
        while (copied < to_read)
        {
            size_t space_to_end = m_ring_buffer_size - read_ptr;
            size_t chunk = std::min(to_read - copied, space_to_end);
            
            memcpy(buffer + total_read + copied, ring_buffer.data() + read_ptr, chunk);
            
            read_ptr = (read_ptr + chunk) % m_ring_buffer_size;
            copied += chunk;
        }

        total_read += to_read;
        m_logical_position += to_read;
        
        // -----------------------------------------------------
        // Lazy Pruning: 检查并丢弃过老的历史数据
        // -----------------------------------------------------
        // 注意：这里我们使用最新的 m_logical_position 和当前的 buf_start 比较
        // buf_start (tail) 只有在这里才会被修改
        
        int64_t current_history = m_logical_position - buf_start; 
        if (current_history > (int64_t)m_cfg_history_size)
        {
            size_t bytes_to_drop = (size_t)(current_history - (int64_t)m_cfg_history_size);
            // 限制不超过 m_rb_bytes_available (虽不应发生)
            if (bytes_to_drop > m_rb_bytes_available) bytes_to_drop = m_rb_bytes_available;

            if (bytes_to_drop > 0)
            {
                m_ring_buffer_tail = (m_ring_buffer_tail + bytes_to_drop) % m_ring_buffer_size;
                m_rb_bytes_available -= bytes_to_drop;
                m_cv_writer.notify_one(); // 通知 Worker 有空位
            }
        }
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
        if (whence == SEEK_SET && position == 0)
        {
            // allowed
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

    // kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Seek() 请求 %lld (模式: %d). 更新逻辑位置 (原: %lld).", target_pos, whence, m_logical_position);

    m_logical_position = target_pos; 

    // Lazy Seek: 这里不做任何网络操作，全部推迟到 Read() 中处理。
    return m_logical_position;
}

bool CCurlBuffer::CreateMiddleCache(int64_t start_pos)
{
    // 简化逻辑：只要曾经建立过热点缓存，就认为已就绪 (返回 true)
    if (m_middle_valid_from != -1) 
    {
        return true;
    }
    
    // **全局缓存检查**: 如果当前实例没有，先查查全局有没有
    {
        std::lock_guard<std::mutex> lock(g_data_cache_mutex);
        if (g_data_cache.url == m_file_url && g_data_cache.middle_valid_from != -1)
        {
            m_middle_buffer = g_data_cache.middle_buffer;
            m_middle_valid_from = g_data_cache.middle_valid_from;
            kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [JIT] 命中全局热点缓存 (复用). Valid: %lld", m_middle_valid_from);
            return true;
        }
    }

    // 计算预计下载大小 (处理 EOF 边界)
    size_t expected_size = m_cfg_middle_size;
    if (m_total_size > 0 && start_pos + (int64_t)expected_size > m_total_size)
    {
        int64_t remaining = m_total_size - start_pos;
        if (remaining < 0) remaining = 0;
        expected_size = (size_t)remaining;
    }

    if (expected_size == 0) return false;

    // 分配或调整内存
    if (!m_middle_buffer) {
        // 场景 A: 首次分配，直接指定大小，一步到位
        m_middle_buffer = std::make_shared<std::vector<uint8_t>>(expected_size);
    }
    else if (m_middle_buffer->size() != expected_size) {
        // 场景 B: 复用已有内存，仅调整大小
        m_middle_buffer->resize(expected_size); 
    }

    // 获取 handle
    CURL* curl = GetCurlHandleFromPool();
    if (!curl) return false;

    curl_easy_reset(curl);
    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [JIT] 开始同步下载热点数据. Start: %lld, Size: %zu", start_pos, m_middle_buffer->size());

    bool success = DownloadRange(curl, start_pos, m_middle_buffer->size(), *m_middle_buffer);
    
    ReturnCurlHandleToPool(curl);

    if (success)
    {
        m_middle_valid_from = start_pos;
        
        // 更新全局缓存
        {
             std::lock_guard<std::mutex> lock(g_data_cache_mutex);
             if (g_data_cache.url == m_file_url)
             {
                 g_data_cache.middle_buffer = m_middle_buffer;
                 g_data_cache.middle_valid_from = m_middle_valid_from;
             }
        }
        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [JIT] 热点数据下载成功.");
        return true;
    }
    else
    {
        kodi::Log(ADDON_LOG_ERROR, "FastVFS: [JIT] 热点数据下载失败.");
        // 失败意味着没法用 Cache
        m_middle_valid_from = -1;
        return false;
    }
}
