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

## 许可证

本软件采用 [GNU General Public License v2+ (GPL-2.0-or-later)](LICENSE.txt) 授权，与 Kodi 项目保持一致。
