#pragma once

#include <kodi/addon-instance/VFS.h>
#include "CurlBuffer.h"

// ---------------------------------------------------------------------------
// CClientVFS: 插件主入口
// ---------------------------------------------------------------------------
// 负责实现 Kodi 的 VFS 接口，并将请求转发给我们自己的缓存核心 (CCurlBuffer)
// ---------------------------------------------------------------------------
class CClientVFS : public kodi::addon::CInstanceVFS
{
public:
  CClientVFS(const kodi::addon::IInstanceInfo& instance);
  ~CClientVFS() override = default;

  // --- 核心 IO 接口 ---
  kodi::addon::VFSFileHandle Open(const kodi::addon::VFSUrl& url) override;

  ssize_t Read(kodi::addon::VFSFileHandle context, uint8_t* buffer, size_t uiBufSize) override;

  int64_t Seek(kodi::addon::VFSFileHandle context, int64_t position, int whence) override;

  int64_t GetPosition(kodi::addon::VFSFileHandle context) override;

  int64_t GetLength(kodi::addon::VFSFileHandle context) override;

  bool Close(kodi::addon::VFSFileHandle context) override;

  // --- 属性接口 ---
  int Stat(const kodi::addon::VFSUrl& url, kodi::vfs::FileStatus& buffer) override;
  
  bool Exists(const kodi::addon::VFSUrl& url) override;
  
  // 必须返回 true，否则播放器可能会禁用进度条拖动
  bool IoControlGetSeekPossible(kodi::addon::VFSFileHandle context) override { return true; }
  
  // 告诉 Kodi 我们想要大块读取 (虽然 Kodi 内部通过 CDVDInputStream 可能会自己分片，但也是一种暗示)
  int GetChunkSize(kodi::addon::VFSFileHandle context) override { return 4 * 1024 * 1024; }
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
