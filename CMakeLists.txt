project(coro-cloudstorage-fuse)
cmake_minimum_required(VERSION 3.17)

add_subdirectory(contrib/coro-cloudstorage EXCLUDE_FROM_ALL)

add_executable(coro-cloudstorage-fuse)

target_sources(coro-cloudstorage-fuse PRIVATE
    src/main.cc)

if(WIN32)
    target_sources(coro-cloudstorage-fuse PRIVATE 
        src/fuse_winfsp.h
        src/fuse_winfsp.cc)
endif()

if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "4")
    set(ARCH x86)
else()
    set(ARCH x64)
endif()

find_library(winfsp_LIBRARY NAMES winfsp-${ARCH} PATHS $ENV{PROGRAMFILES\(x86\)}/WinFsp/lib REQUIRED)
find_path(winfsp_INCLUDE winfsp/winfsp.h PATHS PATHS $ENV{PROGRAMFILES\(x86\)}/WinFsp/inc REQUIRED)

if(MSVC)
    set_target_properties(coro-cloudstorage-fuse PROPERTIES LINK_FLAGS "/DELAYLOAD:winfsp-${ARCH}.dll delayimp.lib" )
    target_compile_options(coro-cloudstorage-fuse PRIVATE "/bigobj")
endif()

target_link_libraries(coro-cloudstorage-fuse PRIVATE coro-cloudstorage ${winfsp_LIBRARY})
target_include_directories(coro-cloudstorage-fuse PRIVATE ${winfsp_INCLUDE})