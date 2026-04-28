中文 | [English](README.md)

# vfs.stream.fast

**基于 LRU 块缓存的 WebDAV(s) 和 HTTP(s) Kodi VFS 实现。**  
专为 `webdav(s)` / `http(s)` 协议优化，通过 LRU 淘汰策略缓存文件块，加速蓝光ISO原盘的起播速度。  
安装后默认参数下，绝大多数 ISO 文件可在 5 秒内开始播放。

> **注意**：插件会接管一切通过 Kodi VFS 访问的 HTTP/WebDAV 资源，包括播放 MKV/MP4、下载远程海报、从仓库安装插件等。  
> 因 LRU 块缓存机制，MKV 的起播速度可能略差于 Kodi 原版 VFS（差异很小）。

提供 Windows (x64, x86)、Linux (x64, x86, ARM64, ARM)、Android (ARM64, ARMv7)、macOS (x64, ARM64) 构建版本。

## 安装

1. 前往 [Releases](../../releases) 页面。
2. 下载对应您平台的 zip 文件（coreelec ng分支:linux-alinux-armv7,ne分支linux-aarch64,其他平台和安装的kodi版本保持一致即可）。
3. 在 Kodi 中，导航至 **设置** -> **插件** -> **从 zip 文件安装**。
4. 选择下载的 zip 文件。
5. 设置中提供了一些关于块缓存大小和预读缓存等设置，一般情况下，安装即可加速，无需调整设置

也可通过 [repository.forbxy](https://github.com/forbxy/repository.forbxy) 仓库安装，详细信息见仓库项目主页。  
仓库安装会自动匹配操作系统和kodi，推荐  

适配kodi 22的插件在22正式发行之前从actions中下载安装 [action:24951229291](https://github.com/forbxy/vfs.stream.fast/actions/runs/24951229291)


## 源码编译

本项目使用 CMake 和 vcpkg 进行依赖管理。
**注意**：编译需要 Kodi 的 C++ 头文件 (kodi-dev-kit)，因此需要下载 Kodi 源码。

### 前置要求
- CMake
- [vcpkg](https://github.com/microsoft/vcpkg)
- C++ Compiler (MSVC, GCC, Clang)
- **Kodi 源码** (切到对应版本的分支:例如21.x: `Omega`)

### 编译说明 (Windows)

其他平台 (Linux, Android) 的编译或交叉编译请参考 [.github/workflows/build.yml](.github/workflows/build.yml)。

假设您的目录结构如下（vfs 插件和 xbmc 源码并列）：
```text
workspace/
  ├── vfs.stream.fast/
  └── xbmc/  <-- 需要 clone Kodi 源码到这里
```

生成的命令如下：

```bash
# 1. 准备目录结构（如果还没下载 Kodi 源码）
cd ..
git clone https://github.com/xbmc/xbmc.git
cd vfs.stream.fast

# 2. 编译
mkdir build
cd build
# 如果 xbmc 源码不在默认的 ../xbmc，请通过 -DKODI_SOURCE_DIR=/path/to/xbmc 指定
cmake .. -DCMAKE_TOOLCHAIN_FILE=[path/to/vcpkg]/scripts/buildsystems/vcpkg.cmake
cmake --build . --config Release
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

## 支持作者

<img src="resources/support.jpg" width="300" />
