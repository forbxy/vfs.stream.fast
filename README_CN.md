中文 | [English](README.md)

# vfs.stream.fast

**带头尾缓存优化的 WebDAV(s) 和 HTTP(s) Kodi VFS 实现。**

此插件通过预先缓存文件的头部和尾部，加速网络协议下大文件（如 ISO）的播放。

## 特性

- **协议支持**: 专为 `webdav(s)` 和 `http(s)` 协议优化。
- **缓存优化**: 预缓存文件头尾以提高访问速度，减少网络IO等待。
- **跨平台**: 提供 Windows (x64, x86), Linux (x64, x86, ARM64, ARM) 和 Android (ARM64, ARMv7) 的构建版本。

## 安装

1. 前往 [Releases](../../releases) 页面。
2. 下载对应您平台的 zip 文件（例如 Android TV/Shield 下载 `android-aarch64`，PC 下载 `windows-x86_64`）。
3. 在 Kodi 中，导航至 **设置** -> **插件** -> **从 zip 文件安装**。
4. 选择下载的 zip 文件。

## 源码编译

本项目使用 CMake 和 vcpkg 进行依赖管理。

### 前置要求
- CMake
- vcpkg
- C++ Compiler (MSVC, GCC, Clang)

### 编译说明

```bash
mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=[path to vcpkg]/scripts/buildsystems/vcpkg.cmake
cmake --build .
```

## 关于 STRM

1. **URL 路径要求**
   `.strm` 文件中的 URL path 结尾必须包含文件扩展名，否则无法起播 ISO。推荐填写 WebDAV 的标准地址。
   
   *   ❌ `https://115.com/storage/linkshared` (结尾没有扩展名)
   *   ❌ `https://115.com/storage/linkshared?file=1.iso` (扩展名在问号参数后面，无效)
   *   ✅ `https://115.com/storage/linkshared.iso` (正确)
   *   ✅ `https://115.com/storage/linkshared.iso?a=b&c=d` (正确)

   **总结**：URL 问号（如果有）前面的部分必须包含文件格式（扩展名）。这是 Kodi 插件机制的限制，无法绕过。

2. **字幕与播放卡顿问题**
   例如 URL 为 `https://115.com/storage/linkshared.iso?a=b&c=d`，文件名为 `linkshared.iso`，Kodi 会尝试访问父目录 `https://115.com/storage/` 寻找字幕。
   如果服务端没有正确实现目录访问（例如返回整个大文件内容），会导致打开蓝光菜单很快，但点击播放后卡住。
   **临时方案**：可以选择“播放主视频”而不是“显示简易蓝光菜单”来绕过此问题。

## 许可证

本软件采用 [GNU General Public License v2+ (GPL-2.0-or-later)](LICENSE.txt) 授权，与 Kodi 项目保持一致。
