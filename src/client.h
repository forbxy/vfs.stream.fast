#pragma once

#include <kodi/addon-instance/VFS.h>
#include "CurlBuffer.h"

#ifdef CreateDirectory
#undef CreateDirectory
#endif

#ifdef RemoveDirectory
#undef RemoveDirectory
#endif

// ---------------------------------------------------------------------------
// CClientVFS: 插件主入口
// ---------------------------------------------------------------------------
// 负责实现 Kodi 的 VFS 接口，并将请求转发给我们自己的缓存核心 (CCurlBuffer)
// ---------------------------------------------------------------------------
class CClientVFS : public kodi::addon::CInstanceVFS
{
public:
  CClientVFS(const kodi::addon::IInstanceInfo& instance);
  ~CClientVFS() override;

  // --- 核心 IO 接口 ---
  kodi::addon::VFSFileHandle Open(const kodi::addon::VFSUrl& url) override;

  kodi::addon::VFSFileHandle OpenForWrite(const kodi::addon::VFSUrl& url, bool overWrite) override;

  ssize_t Read(kodi::addon::VFSFileHandle context, uint8_t* buffer, size_t uiBufSize) override;

  ssize_t Write(kodi::addon::VFSFileHandle context, const uint8_t* buffer, size_t uiBufSize) override;

  int Truncate(kodi::addon::VFSFileHandle context, int64_t size) override;

  int64_t Seek(kodi::addon::VFSFileHandle context, int64_t position, int whence) override;

  int64_t GetPosition(kodi::addon::VFSFileHandle context) override;

  int64_t GetLength(kodi::addon::VFSFileHandle context) override;

  bool Close(kodi::addon::VFSFileHandle context) override;

  // --- 属性接口 ---
  int Stat(const kodi::addon::VFSUrl& url, kodi::vfs::FileStatus& buffer) override;
  
  bool Exists(const kodi::addon::VFSUrl& url) override;

  bool Delete(const kodi::addon::VFSUrl& url) override;

  bool Rename(const kodi::addon::VFSUrl& url, const kodi::addon::VFSUrl& url2) override;

  bool DirectoryExists(const kodi::addon::VFSUrl& url) override;

  bool RemoveDirectory(const kodi::addon::VFSUrl& url) override;

  bool CreateDirectory(const kodi::addon::VFSUrl& url) override;
  
  bool IoControlGetSeekPossible(kodi::addon::VFSFileHandle context) override {
    // Always return true for manifest-type files like MPD.  The seekable=0
    // protocol option applies to the video stream, not the manifest itself.
    // Returning false here causes inputstream.adaptive to reject the stream
    // before even attempting to download the manifest.
    return true;
  }
  
  int GetChunkSize(kodi::addon::VFSFileHandle context) override {
    CCurlBuffer* buf = (CCurlBuffer*)context;
    int chunk = (buf && buf->IsRangeSupported()) ? 256*1024 : 0;
    kodi::Log(ADDON_LOG_DEBUG, "FastVFS: GetChunkSize() called, returning %d", chunk);
    return chunk;
  }
};

// ---------------------------------------------------------------------------
// 工厂类
// ---------------------------------------------------------------------------
class CMyAddon : public kodi::addon::CAddonBase
{
public:
  CMyAddon() = default;
  ADDON_STATUS CreateInstance(const kodi::addon::IInstanceInfo& instance,
                              KODI_ADDON_INSTANCE_HDL& hdl) override;
};
