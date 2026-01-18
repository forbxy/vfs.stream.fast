[中文](README_CN.md) | English

# vfs.stream.fast

**Kodi VFS implementation for WebDAV(s) and HTTP(s) with pre-cached header/footer optimization.**

This addon accelerates the playback of large files (like ISOs) over network protocols by caching the beginning and end of files, reducing latency when seeking or starting playback.

## Features

- **Protocol Support**: Optimized specifically for `webdav(s)` and `http(s)` protocols.
- **Cache Optimization**: Pre-caches the header and footer of files to improve access times.
- **Cross-Platform**: Builds available for Windows (x64, x86), Linux (x64, x86, ARM64, ARM), and Android (ARM64, ARMv7).

## Installation

1. Go to the [Releases](../../releases) page.
2. Download the zip file corresponding to your platform (e.g., `android-aarch64` for Android TV/Shield, `windows-x86_64` for PC).
3. In Kodi, navigate to **Settings** -> **Add-ons** -> **Install from zip file**.
4. Select the downloaded zip file.

## Build from Source

This project uses CMake and vcpkg for dependency management.
**Note**: You need the Kodi C++ headers (kodi-dev-kit) to build this addon, so the Kodi source code is required.

### Prerequisites
- CMake
- [vcpkg](https://github.com/microsoft/vcpkg)
- C++ Compiler (MSVC, GCC, Clang)
- **Kodi Source Code** (Recommended branch: `Omega`)

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
