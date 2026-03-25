#pragma once

#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <curl/curl.h>
#include <kodi/addon-instance/VFS.h>

// ---------------------------------------------------------------------------
// CCurlBuffer: 核心预读引擎
// ---------------------------------------------------------------------------
class CCurlBuffer
{
public:
    CCurlBuffer();
    ~CCurlBuffer();

    // 打开流 (或只获取信息)
    bool Open(const kodi::addon::VFSUrl &url);
    bool Stat(const kodi::addon::VFSUrl &url); // 只发 HEAD 请求
    void Close();

    // 核心读取接口
    ssize_t Read(uint8_t *buffer, size_t size);
    int64_t Seek(int64_t position, int whence);

    // 写入接口 (参考 Kodi CurlFile 的 multi-interface 模式)
    bool OpenForWrite(const kodi::addon::VFSUrl &url, bool overWrite);
    ssize_t Write(const uint8_t *buffer, size_t size);
    int Truncate(int64_t size);

    int64_t GetPosition() const { return m_logical_position; }
    int64_t GetLength() const { return m_total_size; }
    
    // Metadata getters
    bool IsRangeSupported() const { return m_support_range; }
    bool IsDirectory() const { return m_is_directory; }
    time_t GetModificationTime() const { return m_mod_time; }
    time_t GetAccessTime() const { return m_access_time; }

    // Helper for callback
    bool IsTransferAborted() const { return m_abort_transfer; }

    // ISO 延迟关闭支持
    bool IsIsoFile() const { return m_is_iso; }
    const std::string& GetOriginalUrl() const { return m_original_kodi_url; }
    void ResetForReuse(); // 延迟关闭复用时重置逻辑状态

    // 状态控制 (Public allow callback access)
    std::atomic<bool> m_is_running = false;

    // -----------------------------------------------------------------------
    // 可配置参数区 (Configuration)
    // -----------------------------------------------------------------------
    static size_t LRU_BLOCK_SIZE;          // LRU 块大小
    static size_t LRU_TOTAL_SIZE;          // LRU 总大小
    static size_t LRU_MAX_BLOCKS;          // LRU 最大块数
    static void UpdateLRUSettings(size_t block_size, size_t total_size);

    size_t m_cfg_ring_size = 100 * 1024 * 1024;   // 主 RingBuffer 大小

    // -----------------------------------------------------------------------
    // Network Timeouts & Limits
    // -----------------------------------------------------------------------
    long m_net_connect_timeout_sec = 10;
    long m_net_low_speed_time_sec = 15;
    long m_net_worker_low_speed_time_sec = 15; // [New] Worker 专用低速阈值
    long m_net_read_timeout_sec = 20; // [Fix] 提高到20秒，必须大于 LowSpeedTime(15s)，否则低速逻辑无效
    
    // For DownloadRange (Probe/Cache)
    long m_net_range_total_timeout_sec = 20;
    
    int m_net_max_retries = 5;

protected:
    // 工作线程入口
    void WorkerThread();
    void StartWorker(); // 延迟启动 Helper

    // 状态变量
    bool m_support_range = false;
    bool m_is_directory = false;
    bool m_is_video = false;
    bool m_is_iso = false;
    time_t m_mod_time = 0;
    time_t m_access_time = 0;

    // Curl 回调 (Worker专用)
    static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp);
    size_t HandleWrite(void *contents, size_t size);

    // 缓存填充专用
    bool DownloadRange(CURL* curl, int64_t start, int64_t length, std::vector<uint8_t>& buffer);
    static size_t CacheWriteCallback(void *contents, size_t size, size_t nmemb, void *userp);

    // 内部辅助
    void SetupBaseCurlOptions(CURL* curl, const std::string& target_url);
    void SetupStatWebDavOptions(CURL* curl, const std::string& target_url, struct curl_slist** headers_out);
    void SetupStatHeadOptions(CURL* curl, const std::string& target_url);
    void SetupStatGetFallbackOptions(CURL* curl, const std::string& target_url);
    void SetupDownloadRangeOptions(CURL* curl, const std::string& target_url, int64_t start, int64_t length);
    void SetupWorkerDownloadOptions(CURL* curl, const std::string& target_url, int64_t start);

    void UpdateEffectiveUrlFromCurl(CURL* curl, const std::string& original_url, const char* context_name);
    static std::string GetFileExtensionFromUrl(const std::string& url); // [New] Get Extension Helper

    // 写入模式回调 (curl READFUNCTION, 向服务器上传数据)
    static size_t UploadReadCallback(char *buffer, size_t size, size_t nitems, void *userp);

private:
    // 基础信息
    std::string m_file_url;
    std::string m_effective_url; // 跳转后的最终地址 (实例级别)
    std::string m_original_kodi_url; // 原始 Kodi URL (延迟关闭缓存 key)
    std::string m_username;
    std::string m_password;

    int64_t m_total_size = 0;                     // 文件总大小
    int64_t m_logical_position = 0;               // Kodi 认为的播放位置
    std::atomic<int64_t> m_download_position = 0; // 我们实际上从网上下到的位置

    // -----------------------------------------------------
    // 新增：持久化线程控制信号 (Persistent Thread Signals)
    // -----------------------------------------------------
    std::atomic<bool> m_abort_transfer{false};   // 打断当前 curl_easy_perform
    std::atomic<bool> m_trigger_reset{false};    // 触发 RingBuffer 重置
    std::atomic<int64_t> m_reset_target_pos{0}; // 重置后的新下载起点

    std::atomic<bool> m_is_eof = false; // 下载是否结束
    std::atomic<bool> m_has_error = false;

    // 线程
    std::thread m_worker_thread;
    // 环形主缓存
    std::vector<uint8_t> ring_buffer;
    size_t m_ring_buffer_size = 0; // 150MB
    size_t m_ring_buffer_head = 0;
    size_t m_ring_buffer_tail = 0;
    size_t m_rb_bytes_available = 0;


    std::mutex m_ring_buffer_mutex;
    std::condition_variable m_cv_reader; // 读者等数据
    std::condition_variable m_cv_writer; // 写者等空间

    // ----- 写入模式状态 (Write Mode State) -----
    bool m_for_write = false;
    bool m_write_error = false;
    bool m_write_eof = false;
    CURL* m_write_curl = nullptr;
    CURLM* m_write_multi = nullptr;
    int m_write_still_running = 0;

    // 写入缓冲 (READFUNCTION 回调使用)
    const uint8_t* m_write_buffer = nullptr;
    size_t m_write_buffer_size = 0;
    size_t m_write_buffer_pos = 0;
    bool m_write_paused = false;
};
