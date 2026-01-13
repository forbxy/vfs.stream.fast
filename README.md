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

### Prerequisites
- CMake
- vcpkg
- C++ Compiler (MSVC, GCC, Clang)

### Build Instructions

```bash
mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=[path to vcpkg]/scripts/buildsystems/vcpkg.cmake
cmake --build .
```

## License

This software is licensed under the [GNU General Public License v2+ (GPL-2.0-or-later)](LICENSE.txt), consistent with the Kodi project itself.
