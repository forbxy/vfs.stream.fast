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
#include <sstream>

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
    CURLUcode rc = curl_url_set(h, CURLUPART_URL, url.c_str(), 0);
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
    
    // [Fix] Url Cleaning: Remove Kodi options (after '|')
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


    

    // 协议修复: libcurl 不认识 dav://，只认识 http://
    // [Fix] 检测 WebDAV (Check protocol before modification)
    bool isWebDav = (m_file_url.rfind("dav://", 0) == 0) || (m_file_url.rfind("davs://", 0) == 0);

    if (m_file_url.rfind("dav://", 0) == 0)
        m_file_url.replace(0, 6, "http://");
    else if (m_file_url.rfind("davs://", 0) == 0)
        m_file_url.replace(0, 7, "https://");

    // 保存原始地址以用作缓存 Key
    std::string original_url = m_file_url;
    
    // [Init] 初始化 ISO 标志
    std::string ext = GetFileExtensionFromUrl(original_url);
    m_is_iso = (ext == "iso");
    // [Init] 初始化 Video 标志
    m_is_video = (ext == "mkv" || ext=="iso" || ext == "mp4" || ext == "avi" || ext == "mov" ||  
                  ext == "wmv" || ext == "flv" || ext == "webm" || ext == "m2ts" || 
                  ext == "ts" || ext == "bdmv" || ext == "ifo" || ext == "3gp" ||
                  ext == "rmvb" || ext =="rm" || ext == "vob" || ext == "mpg" || 
                  ext == "mpeg" );

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

    // =========================================================================
    // 策略分支: WebDAV (PROPFIND) vs HTTP (HEAD)
    // =========================================================================

    // =========================================================================
    // 1. 统一 Stat 重试循环 (WebDAV与HTTP共用)
    // =========================================================================
    
    struct curl_slist *headers = NULL;
    std::string resp_body;
    int retries = 0;
    char errbuf[CURL_ERROR_SIZE];

    while (retries < m_net_max_retries)
    {
        curl_easy_reset(curl);
        errbuf[0] = 0;
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

        if (isWebDav)
        {
             // WebDAV Setup
             if (headers) { curl_slist_free_all(headers); headers = NULL; }
             resp_body.clear(); 
             
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

        if (res == CURLE_OK) break;

        // Fatal Error Check
        if (IsFatalError(res))
        {
             kodi::Log(ADDON_LOG_ERROR, "FastVFS: Stat WebDAV/HTTP Fatal Error %d. Aborting. Detail: %s", res, errbuf);
             if (res != CURLE_GOT_NOTHING) {
                 std::lock_guard<std::mutex> l(g_redirect_cache_mutex); 
                 g_redirect_cache.erase(m_file_url); 
             }
             break;
        }
        
        kodi::Log(ADDON_LOG_WARNING, "FastVFS: Stat Error %d. Retry %d/%d. Detail: %s", res, retries+1, m_net_max_retries, errbuf);
        
        std::lock_guard<std::mutex> l(g_redirect_cache_mutex); g_redirect_cache.erase(m_file_url);
        
        retries++;
        if (retries < m_net_max_retries) std::this_thread::sleep_for(std::chrono::milliseconds(200));
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
             kodi::Log(ADDON_LOG_WARNING, "FastVFS: Stat HEAD failed with Error 52 (Empty Reply). Server likely does not support HEAD. Fallback to GET 0-1...");
             need_fallback = true;
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

    // FIXME 应该在拿到最终的链接后使用所有的跳转路径判断文件格式，目前在UpdateRedirectCacheFromCurl
    // 里更新is_iso标志，和整体的逻辑有点不一致

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
               g_stat_cache[m_file_url] = entry;
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
    m_file_url = url.GetURL();

    // [Fix] Url Cleaning: Remove Kodi options (after '|')
    size_t pipe_pos = m_file_url.find('|');
    if (pipe_pos != std::string::npos) {
        m_file_url = m_file_url.substr(0, pipe_pos);
    }

    if (IsLikelyDoubleEncoded(m_file_url)) {
        kodi::Log(ADDON_LOG_WARNING, "FastVFS: [Warning] Open() 检测到可能的二次编码 URL (Count >= 2)! (Contains %%25+Hex)");
        kodi::Log(ADDON_LOG_WARNING, "FastVFS: Original URL: %s", m_file_url.c_str());

        std::string fixed_url_preview = m_file_url;
        FixDoubleEncoding(fixed_url_preview);
        kodi::Log(ADDON_LOG_WARNING, "FastVFS: Fixed URL (Preview): %s", fixed_url_preview.c_str());

        // [Reserved] 自动修复代码保留但不执行
        if (false) FixDoubleEncoding(m_file_url);
    }

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
    // [Fix] 静态缓存控制 (Static Cache Controller)
    // -------------------------------------------------------------
    
    // 默认启用，后面根据条件禁用
    m_disable_static_caches = false;
    
    // [Small File Optimization] 2MB 以下文件: 强制开启全量缓存，不启动 Worker
    // 修改为: 如果文件体积 <= 头部缓存配置的 90% (e.g. 30MB -> 27MB), 视为小文件
    int64_t small_file_thresh = (int64_t)(m_cfg_head_size * 0.9);
    bool is_small_file = (m_total_size > 0 && m_total_size <= small_file_thresh);

    if (is_small_file)
    {
        m_cfg_head_size = (size_t)m_total_size;
        m_cfg_tail_size = 0; // 头部已覆盖全文，无需尾部
        // 注意：不禁用 static caches，反而是依靠 static caches 来做 Full Cache
        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [优化] 小文件 (%lld <= %lld) -> 启用全量缓存模式.", m_total_size, small_file_thresh);
    }

    // 1. 如果文件长度未知 (<=0) -> 禁用静态缓存，仅流式
    if (m_total_size <= 0) {
        m_disable_static_caches = true;
        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: 文件长度未知 (0), 禁用静态缓存模式, 仅使用流式.");
    }
    // 2. 如果开启了 [仅ISO缓存] 且当前文件不是ISO -> 禁用静态缓存
    // 这涵盖了所有 mp4/mkv/ts 等容器，以及任何只要不是 ISO 的文件
    // [Fix] 如果是小文件优化模式，忽略 ISO 限制
    else if (m_cfg_cache_iso_only && !m_is_iso && !is_small_file) {
         m_disable_static_caches = true;
         // 获取扩展名仅用于日志
         std::string ext = GetFileExtensionFromUrl(m_file_url);
         kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [Config] 仅ISO开启缓存，非ISO文件 (Ext: %s) -> 禁用静态缓存.", ext.c_str());
    }


    // 3. (Fallback) 如果缓存尚未禁用，但文件太小 (< Preload Thresh) -> 禁用静态缓存 (不值得预热)
    // [Fix] 小文件优化模式例外
    if (!m_disable_static_caches && m_total_size < m_cfg_preload_thresh && !is_small_file) {
        m_disable_static_caches = true;
        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: 文件小于阈值 (%lld < %lld), 禁用静态缓存模式, 仅使用流式.", m_total_size, m_cfg_preload_thresh);
    }

    // -------------------------------------------------------------
    // 动态内存策略 (Dynamic Memory Policy)
    // -------------------------------------------------------------
    
    // 1. 小文件全量缓存模式：不需要 RingBuffer
    if (is_small_file)
    {
        m_ring_buffer_size = 0;
        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [Dynamic] 小文件优化 -> 禁用循环缓冲区 (RingBuffer Disabled)，仅使用内存全量缓存.");
    }
    // 2. 如果文件长度未知 (0)，使用保守的 Buffer 大小 (5MB)，避免浪费过多内存，同时保持流式能力
    else if (m_total_size <= 0)
    {
        m_ring_buffer_size = 5 * 1024 * 1024; // 5MB Conservative Buffer
        // [Dynamic] 当长度为0时，直接将历史数据保留设置为0，防止死锁
        m_cfg_history_size = 0;
        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [Dynamic] 未知长度 (0) -> 循环缓冲区: %zu bytes (保守模式), 历史回溯: 0 (已禁用)", m_ring_buffer_size);
    }
    // 3. RingBuffer 大小: 若为常规小文件 (< 配置的 RingBuffer 大小)，Buffer 仅分配文件大小
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

bool CCurlBuffer::PreloadCaches()
{
    // [Fix] 逻辑已移至 Open，从 PreloadCaches 移除
    if (m_disable_static_caches)
    {
         // 已在 Open 中记录日志
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

        SetupWorkerDownloadOptions(curl, target_url, m_download_position);
        
        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Worker 开始下载. Pos: %lld", m_download_position.load());

        CURLcode res = curl_easy_perform(curl);
        
        if (res != CURLE_OK)
        {
             kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Worker 下载结束 (Error/Aborted). Res: %d. Detail: %s", res, errbuf);
        }

        // ---------------------------------------------------------
        // Update Redirect Cache
        // ---------------------------------------------------------
        if (res == CURLE_OK)
        {
            UpdateRedirectCacheFromCurl(curl, m_file_url, "Worker", this);
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

// (Function ProgressCallback removed as it is superseded by WorkerProgressCallback)

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

    bool should_send_auth = true;
    if (target_url != m_file_url)
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
    curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE, (curl_off_t)start);
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

    // [New] 更新累计下载并检查阈值
    // 阈值规则: max(头部+尾部+JIT, 500MB)
    // 注意：只要 m_disable_static_caches 变成 true，就不再变回去
    if (!m_disable_static_caches)
    {
        m_accumulated_download_bytes += size;
        
        // 计算阈值 (动态计算避免初始化顺序问题，且开销极小)
        int64_t threshold = std::max((size_t)(500 * 1024 * 1024), m_cfg_head_size + m_cfg_tail_size + m_cfg_middle_size);
        
        if (m_accumulated_download_bytes > threshold)
        {
            kodi::Log(ADDON_LOG_DEBUG, "FastVFS: 累计下载超过阈值 (%lld > %lld). 屏蔽静态缓存.", 
                (int64_t)m_accumulated_download_bytes, threshold);
            m_disable_static_caches = true;
        }
    }

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
    
    // [Fix] 仅当没有禁用静态缓存时才执行预热检查
    if (!m_disable_static_caches)
    {
        if (!PreloadCaches())
        {
            kodi::Log(ADDON_LOG_ERROR, "FastVFS: Read 失败 - 预热缓存下载失败");
            return -1; // 返回 -1 表示读错误
        }
    }

    std::unique_lock<std::mutex> lock(m_ring_buffer_mutex);
    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Read() 请求 %zu bytes (Pos: %lld)", size, m_logical_position);

    // [EOF Check] 
    if (m_total_size > 0 && m_logical_position >= m_total_size)
    {
         kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Read() EOF Reached (Pos >= Total). Returning 0.");
         return 0;
    }

    size_t total_read = 0;

    // ---------------------------------------------------------
    // 1. 优先检查静态缓存 (Static Caches) - 全命中策略
    // ---------------------------------------------------------
    // [New] 超过一定下载量后屏蔽静态缓存，防止大数偏移错误或干扰顺序播放
    if (!m_disable_static_caches)
    {
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
                // [Fix] 32-bit Overflow Fix
                int64_t diff = m_logical_position - m_tail_valid_from;
                
                // 只要 offset 在缓存范围内，我们就拥有直到 EOF 的所有数据。
                if (diff >= 0 && diff < (int64_t)m_tail_buffer->size())
                {
                    size_t offset = (size_t)diff;
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
        // [Fix] 只有当文件大小已知 (>0) 时才允许使用 JIT 缓存。未知大小时无法计算 Range。
        if (!m_worker_thread.joinable() && m_total_size > 0)
        {
            // 尝试获取或创建 JIT Cache
            // CreateMiddleCache 内部会检查是否已存在有效的覆盖
            // 注意：原本只针对 Random Seek，现在根据指示，对于 !Worker 的情况直接依赖 JIT
            
            // [Optimization] 将下载起始位置向前移动 10%，增加命中几率并覆盖可能的小幅回跳
            int64_t back_offset = (int64_t)(m_cfg_middle_size / 10);
            int64_t adjusted_start = (m_logical_position > back_offset) ? (m_logical_position - back_offset) : 0;
            
            if (!CreateMiddleCache(adjusted_start))
            {
                kodi::Log(ADDON_LOG_ERROR, "FastVFS: CreateMiddleCache 下载失败，Read 终止.");
                return -1;
            }
        }

        // 尝试从 JIT 缓存读取 (CreateMiddleCache 成功后，这里一定会命中，除非 Cache 大小设计问题)
        if (m_middle_valid_from != -1 && m_logical_position >= m_middle_valid_from)
        {
            // [Fix] 32-bit Overflow Fix
            int64_t diff = m_logical_position - m_middle_valid_from;
            
            if (diff >= 0 && diff < (int64_t)m_middle_buffer->size())
            {
                size_t offset = (size_t)diff;
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
                // [Request] 针对 ISO 文件，禁用 JIT 接力机制 (避免频繁触发 Worker)
                bool is_covered_to_eof = (m_total_size > 0 && (m_middle_valid_from + (int64_t)m_middle_buffer->size() >= m_total_size));

                // [Optimized] 使用成员变量 m_is_iso，该变量会在 Stat/DownloadRange 的重定向中自动更新
                if (!m_worker_thread.joinable() && !is_covered_to_eof && !m_is_iso && offset > m_middle_buffer->size() / 2)
                {
                    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [JIT] 检测到连续读取 (Offset: %zu > Half), 提前启动 Worker 接力.", offset);
                    StartWorker();
                }

                return to_copy;
            }
        }
    } // End of m_disable_static_caches check

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
    // 情况 B: 超前 (Too Far) - 超出计划范围，或者虽然在计划内但差距过大
    // 如果 Seek 到很远的位置，超过了这个范围，与其等待下载这一大段无用数据，不如直接重置
    // [Fix] 增加 gap > 20MB 的判断。即使 Buffer 很大(100MB+)，如果 gap 很大，等待下载不如重新连接快。
    else if (m_logical_position > plan_limit || (m_logical_position - buffer_valid_end) > (16 * 1024 * 1024))
    {
        kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Read 超前 (Too Far/Gap > 16MB). Req: %lld, Limit: %lld, Gap: %lld. 触发瞬移.", 
            m_logical_position, plan_limit, (int64_t)(m_logical_position - buffer_valid_end));
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
            // [FIX DEADLOCK]: Seek 导致的死锁修复
            // 当 Seek 向前跳跃 (gap within plan) 时，m_logical_position 超过了 m_download_position。
            // 此时 Reader 进入 wait (等待数据下载)。
            // 但如果缓冲区已满 (m_rb_bytes_available == Size)，Writer 线程正阻塞在 wait(m_cv_writer) 等待空间。
            // Reader 等 Writer，Writer 等 Reader -> 死锁。
            // 解决方法：在 Reader 进入 wait 前，检查是否因为 Seek 跳过了旧数据，导致可以释放大量空间。
            // 如果 "已消费+跳过" 的历史数据量 >HistorySize，则主动丢弃，释放 m_rb_bytes_available 并唤醒 Writer。

            int64_t effective_history = m_logical_position - buf_start; // 从 Buffer 起始点到当前请求点的距离
            if (effective_history > (int64_t)m_cfg_history_size)
            {
                size_t bytes_to_drop = (size_t)(effective_history - (int64_t)m_cfg_history_size);
                
                // 限制不能丢弃超过实际拥有的数据
                if (bytes_to_drop > m_rb_bytes_available) 
                    bytes_to_drop = m_rb_bytes_available;

                if (bytes_to_drop > 0)
                {
                    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Read 死锁预防 - 主动丢弃 %zu bytes (Seek Gap). Avail Before: %zu", 
                        bytes_to_drop, m_rb_bytes_available);

                    m_ring_buffer_tail = (m_ring_buffer_tail + bytes_to_drop) % m_ring_buffer_size;
                    m_rb_bytes_available -= bytes_to_drop;
                    
                    // 关键: 唤醒 Writer 起来干活
                    m_cv_writer.notify_all(); 
                    
                    // 重新计算 avail (虽然仍是 <=0，但 Buffer 有空间了，Writer 可以继续跑)
                    // buf_start = m_download_position - m_rb_bytes_available; 
                }
            }

            // 数据不够，需要等待
            if (m_is_eof) return total_read; // 已经读到文件末尾
            if (m_has_error) return -1;
            
            // kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Read Waiting... (Pos: %lld, BufStart: %lld, BufEnd: %lld)", m_logical_position, buf_start, buf_end);

            // [Fix] 增加等待超时保护 (改为60秒，不做主动重置)
            // 原逻辑：15秒超时后会主动触发 Worker 重置 (Seek 重连)
            // 新逻辑：等待 60 秒，如果还等不到直接报错。网络层的重连交给 Worker 自己处理。
            if (m_cv_reader.wait_for(lock, std::chrono::seconds(60)) == std::cv_status::timeout)
            {
                kodi::Log(ADDON_LOG_ERROR, "FastVFS: Read 严重超时 (60s). 缓冲区无数据，强制返回错误 (-1) 以中断播放。");
                // 强制返回 -1，即使之前可能读到了一点点数据也不返回了，直接让播放器报错更干脆
                return -1; 
            }

            // 被 Worker 唤醒（或有错误/EOF）
            if (m_has_error) return -1;
            if (m_is_eof && m_rb_bytes_available == 0) return total_read; // 双重检查

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

    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: Seek() 请求 %lld (模式: %d). 更新逻辑位置 (原: %lld).", target_pos, whence, m_logical_position);

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
            kodi::Log(ADDON_LOG_DEBUG, "FastVFS: [JIT] 复用全局热点缓存. Valid: %lld", m_middle_valid_from);
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
