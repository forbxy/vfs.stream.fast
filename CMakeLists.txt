cmake_minimum_required(VERSION 3.15)
project(vfs.stream.fast)

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# -----------------------------------------------------------------------------
# 1. KODI SDK PATH (Flexible)
# -----------------------------------------------------------------------------
# 允许通过命令行 -DKODI_SOURCE_DIR=... 传入，或者默认查找 ../xbmc
if(NOT DEFINED KODI_SOURCE_DIR)
    set(KODI_SOURCE_DIR "${CMAKE_SOURCE_DIR}/../xbmc")
endif()

if(EXISTS "${KODI_SOURCE_DIR}/xbmc/addons/kodi-dev-kit/include/kodi/addon-instance/VFS.h")
    message(STATUS "Found Kodi Source: ${KODI_SOURCE_DIR}")
else()
    message(WARNING "Kodi source not found at: ${KODI_SOURCE_DIR}. \n Headers might be missing!")
endif()

# -----------------------------------------------------------------------------
# 2. INCLUDES
# -----------------------------------------------------------------------------
include_directories(
    ${KODI_SOURCE_DIR}/xbmc/addons/kodi-dev-kit/include
    ${KODI_SOURCE_DIR}/xbmc/addons/kodi-dev-kit/include/kodi
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# -----------------------------------------------------------------------------
# 3. CURL (Standard find_package)
# -----------------------------------------------------------------------------
# 强制使用 CONFIG 模式查找，这对 vcpkg 静态库至关重要
# 否则默认的 Module 模式可能会遗漏静态库依赖或找不到 targets
find_package(CURL CONFIG REQUIRED)

# 如果是 Android，vcpkg 可能会构建出名为 curl::curl 的 target
if(TARGET CURL::libcurl)
    set(CURL_TARGET CURL::libcurl)
    message(STATUS "Found CURL::libcurl")
elseif(TARGET CURL::curl)
    set(CURL_TARGET CURL::curl)
    message(STATUS "Found CURL::curl")
else()
    # Fallback (不太可能进入这里，如果使用了 CONFIG REQUIRED)
    set(CURL_TARGET ${CURL_LIBRARIES})
    include_directories(${CURL_INCLUDE_DIRS})
endif()

message(STATUS "Using CURL Target: ${CURL_TARGET}")

if(MSVC)
    add_compile_options(/utf-8)
    add_definitions(-DNOMINMAX -D_CRT_SECURE_NO_WARNINGS)
    # 强制声明静态库宏，确保 Windows 下不产生 dllimport 符号
    add_definitions(-DCURL_STATICLIB)
endif()

# -----------------------------------------------------------------------------
# 4. SOURCE FILES
# -----------------------------------------------------------------------------
set(SOURCE_FILES
    src/client.cpp
    src/client.h
    src/CurlBuffer.cpp
    src/CurlBuffer.h
)

# -----------------------------------------------------------------------------
# 5. TARGET & DEFINITIONS
# -----------------------------------------------------------------------------
add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES})

target_link_libraries(${PROJECT_NAME} PRIVATE ${CURL_TARGET})

if(WIN32)
    target_compile_definitions(${PROJECT_NAME} PRIVATE TARGET_WINDOWS)
elseif(ANDROID)
    target_compile_definitions(${PROJECT_NAME} PRIVATE TARGET_ANDROID)
    # Ensure Large File Support on 32-bit Android
    target_compile_definitions(${PROJECT_NAME} PRIVATE -D_FILE_OFFSET_BITS=64)
    target_link_libraries(${PROJECT_NAME} PRIVATE log) # Link Android Log
    # Release 模式下去除符号表，减小体积
    target_link_options(${PROJECT_NAME} PRIVATE $<$<CONFIG:Release>:-s>)
elseif(UNIX AND NOT APPLE)
    target_compile_definitions(${PROJECT_NAME} PRIVATE TARGET_LINUX)
    # Ensure Large File Support on 32-bit Linux
    target_compile_definitions(${PROJECT_NAME} PRIVATE -D_FILE_OFFSET_BITS=64)
    # Release 模式下去除符号表，减小体积
    target_link_options(${PROJECT_NAME} PRIVATE $<$<CONFIG:Release>:-s>)
endif()

# -----------------------------------------------------------------------------
# 6. PACKAGE / INSTALL
# -----------------------------------------------------------------------------
# 生成 zip 结构
install(TARGETS ${PROJECT_NAME} 
    LIBRARY DESTINATION . 
    RUNTIME DESTINATION .
)
install(FILES addon.xml DESTINATION .)
if(EXISTS "resources")
    install(DIRECTORY resources DESTINATION .)
endif()

# CPack 配置 (可选)
set(CPACK_GENERATOR "ZIP")
include(CPack)
