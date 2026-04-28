[中文](README_CN.md) | English

# vfs.stream.fast

**Kodi VFS implementation for WebDAV(s) and HTTP(s) with LRU block cache optimization.**  
Optimized for `webdav(s)` / `http(s)` protocols, uses LRU eviction to cache file blocks, accelerating Blu-ray ISO startup.  
With default settings, most ISOs start playback within 5 seconds.

> **Note**: This addon intercepts all HTTP/WebDAV traffic through Kodi VFS, including MKV/MP4 playback, remote poster downloads, and repository installs.  
> Due to LRU block caching, MKV startup may be slightly slower than Kodi's native VFS (a small difference).

Builds available for Windows (x64, x86), Linux (x64, x86, ARM64, ARM), Android (ARM64, ARMv7), macOS (x64, ARM64).

## Installation

1. Go to the [Releases](../../releases) page.
2. Download the zip file matching your platform (CoreELEC ng: `linux-armv7`, ne: `linux-aarch64`; other platforms match your Kodi version).
3. In Kodi, navigate to **Settings** -> **Add-ons** -> **Install from zip file**.
4. Select the downloaded zip file.
5. The addon provides block cache size and read-ahead settings. Default values should work out of the box.

Also available via the [repository.forbxy](https://github.com/forbxy/repository.forbxy) repository (recommended, auto-matches your OS and Kodi version).

For Kodi 22 builds (before official release), download from [Actions #24951229291](https://github.com/forbxy/vfs.stream.fast/actions/runs/24951229291).

## Build from Source

This project uses CMake and vcpkg for dependency management.
**Note**: You need the Kodi C++ headers (kodi-dev-kit) to build this addon, so the Kodi source code is required.

### Prerequisites
- CMake
- [vcpkg](https://github.com/microsoft/vcpkg)
- C++ Compiler (MSVC, GCC, Clang)
- **Kodi Source Code** (checkout the branch matching your target version, e.g. `Omega` for 21.x)

### Build Instructions (Windows)

For compilation or cross-compilation on other platforms (Linux, Android), please refer to [.github/workflows/build.yml](.github/workflows/build.yml).

Assuming your directory structure is as follows (vfs addon and xbmc source side-by-side):
```text
workspace/
  ├── vfs.stream.fast/
  └── xbmc/  <-- Clone Kodi source code here
```

Build commands:

```bash
# 1. Prepare directory structure (if you haven't cloned Kodi yet)
cd ..
git clone https://github.com/xbmc/xbmc.git
cd vfs.stream.fast

# 2. Build
mkdir build
cd build
# If xbmc source is not in ../xbmc, specify it via -DKODI_SOURCE_DIR=/path/to/xbmc
cmake .. -DCMAKE_TOOLCHAIN_FILE=[path/to/vcpkg]/scripts/buildsystems/vcpkg.cmake
cmake --build . --config Release
```

## About STRM files

1. **URL Path Requirements**
   The URL path inside the `.strm` file must end with the file extension; otherwise, ISO playback will fail. Standard WebDAV URLs are recommended.

   *   ❌ `https://115.com/storage/linkshared` (No extension at the end of path)
   *   ❌ `https://115.com/storage/linkshared?file=1.iso` (Extension is in query parameters, invalid)
   *   ✅ `https://115.com/storage/linkshared.iso` (Correct)
   *   ✅ `https://115.com/storage/linkshared.iso?a=b&c=d` (Correct)

   **Summary**: The part of the URL before the question mark (if any) must contain the file extension. This is a limitation of Kodi's plugin architecture and cannot be bypassed.

2. **Subtitle Scanning & Playback Stalling**
   For a URL like `https://115.com/storage/linkshared.iso?a=b&c=d`, Kodi will attempt to access the parent directory `https://115.com/storage/` to scan for subtitles.
   If the server does not handle this directory request correctly (e.g., returns the full file content instead of a listing), it may cause playback to stall after the Blu-ray menu.
   **Workaround**: You can bypass this issue by choosing "Play main title" instead of "Show simplified menu".

## License

This software is licensed under the [GNU General Public License v2+ (GPL-2.0-or-later)](LICENSE.txt), consistent with the Kodi project itself.

## Support

USDT_ERC20: `0xa7475effb3f2c5fcb618e8052fc4c45ccc9d9710`  
BTC: `bc1qa77v8als2f7qradmtmjjy5ad057q9yws6nanx6`