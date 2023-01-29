cmake_minimum_required(VERSION 3.23)
project(coro-cloudstorage-fuse)

set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/lib" IS_SYSTEM_DIR)
if("${IS_SYSTEM_DIR}" STREQUAL "-1")
    set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
endif()

if(WIN32)
    set(OPTIONS WIN32)
endif()

add_executable(coro-cloudstorage-fuse ${OPTIONS})

target_sources(coro-cloudstorage-fuse PRIVATE
    src/main.cc
    src/coro/cloudstorage/fuse/sparse_file.h
    src/coro/cloudstorage/fuse/sparse_file.cc
    src/coro/cloudstorage/fuse/streaming_write.h
    src/coro/cloudstorage/fuse/streaming_write.cc
    src/coro/cloudstorage/fuse/item_context.h
    src/coro/cloudstorage/fuse/item_context.cc
    src/coro/cloudstorage/fuse/filesystem_context.h
    src/coro/cloudstorage/fuse/filesystem_context.cc
    src/coro/cloudstorage/fuse/filesystem_provider.h
    src/coro/cloudstorage/fuse/filesystem_provider.cc
)

find_package(coro-cloudstorage REQUIRED)

target_link_libraries(coro-cloudstorage-fuse PRIVATE coro::coro-cloudstorage)
target_include_directories(coro-cloudstorage-fuse PRIVATE src)

if(WIN32)
    configure_file(src/resources.rc.in resources.rc)
    target_sources(coro-cloudstorage-fuse PRIVATE
        resources.rc
        src/coro/cloudstorage/fuse/fuse_winfsp_context.h
        src/coro/cloudstorage/fuse/fuse_winfsp_context.cc
        src/coro/cloudstorage/fuse/fuse_winfsp.h
        src/coro/cloudstorage/fuse/fuse_winfsp.cc)

    if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "4")
        set(ARCH x86)
    else()
        set(ARCH x64)
    endif()

    find_library(winfsp_LIBRARY NAMES winfsp-${ARCH} PATHS $ENV{PROGRAMFILES\(x86\)}/WinFsp/lib REQUIRED)
    find_path(winfsp_INCLUDE winfsp/winfsp.h PATHS PATHS $ENV{PROGRAMFILES\(x86\)}/WinFsp/inc REQUIRED)

    target_link_libraries(coro-cloudstorage-fuse PRIVATE ${winfsp_LIBRARY} mpr ntdll)
    target_include_directories(coro-cloudstorage-fuse PRIVATE ${winfsp_INCLUDE})

    if(MSVC)
        set_target_properties(coro-cloudstorage-fuse PROPERTIES
                              LINK_FLAGS "/DELAYLOAD:winfsp-${ARCH}.dll delayimp.lib")
    endif()
else()
    target_sources(coro-cloudstorage-fuse PRIVATE
        src/coro/cloudstorage/fuse/fuse_posix_context.h
        src/coro/cloudstorage/fuse/fuse_posix_context.cc
        src/coro/cloudstorage/fuse/fuse_posix.cc
        src/coro/cloudstorage/fuse/fuse_posix.h)

    include(FindPkgConfig)
    pkg_check_modules(fuse IMPORTED_TARGET fuse3)
    if(NOT fuse_FOUND)
        pkg_check_modules(fuse REQUIRED IMPORTED_TARGET fuse)
        target_sources(coro-cloudstorage-fuse PRIVATE
            src/coro/cloudstorage/fuse/fuse_posix_compat.h
            src/coro/cloudstorage/fuse/fuse_posix_compat.cc
        )
        target_compile_definitions(coro-cloudstorage-fuse PRIVATE CORO_CLOUDSTORAGE_FUSE2)
    endif()

    find_package(Libevent 2.1.12 REQUIRED)
    target_link_libraries(coro-cloudstorage-fuse PRIVATE PkgConfig::fuse libevent::core)
    target_compile_definitions(coro-cloudstorage-fuse PRIVATE FUSE_USE_VERSION=39)
endif()

target_compile_definitions(coro-cloudstorage-fuse PRIVATE "_FILE_OFFSET_BITS=64")

install(TARGETS coro-cloudstorage-fuse)
