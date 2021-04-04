project(coro-cloudstorage-fuse)
cmake_minimum_required(VERSION 3.17)

add_subdirectory(contrib/coro-cloudstorage EXCLUDE_FROM_ALL)

if(WIN32)
    set(OPTIONS WIN32)
endif()

add_executable(coro-cloudstorage-fuse ${OPTIONS})

target_sources(coro-cloudstorage-fuse PRIVATE
    src/main.cc
    src/filesystem_context.h
    src/filesystem_context.cc)

target_link_libraries(coro-cloudstorage-fuse PRIVATE coro-cloudstorage)

if(WIN32)
    configure_file(src/resources.rc.in resources.rc)
    target_sources(coro-cloudstorage-fuse PRIVATE
        resources.rc
        src/fuse_winfsp.h
        src/fuse_winfsp.cc)

    if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "4")
        set(ARCH x86)
    else()
        set(ARCH x64)
    endif()

    find_library(winfsp_LIBRARY NAMES winfsp-${ARCH} PATHS $ENV{PROGRAMFILES\(x86\)}/WinFsp/lib REQUIRED)
    find_path(winfsp_INCLUDE winfsp/winfsp.h PATHS PATHS $ENV{PROGRAMFILES\(x86\)}/WinFsp/inc REQUIRED)

    target_link_libraries(coro-cloudstorage-fuse PRIVATE ${winfsp_LIBRARY} Mpr)
    target_include_directories(coro-cloudstorage-fuse PRIVATE ${winfsp_INCLUDE})

    set_target_properties(coro-cloudstorage-fuse PROPERTIES LINK_FLAGS "/DELAYLOAD:winfsp-${ARCH}.dll delayimp.lib" )
else()
    target_sources(coro-cloudstorage-fuse PRIVATE
        src/fuse_posix.cc
        src/fuse_posix.h)

    include(FindPkgConfig)

    pkg_check_modules(fuse REQUIRED IMPORTED_TARGET fuse3)
    target_link_libraries(coro-cloudstorage-fuse PRIVATE event_pthreads PkgConfig::fuse)
endif()

if(MSVC)
    target_compile_options(coro-cloudstorage-fuse PRIVATE "/bigobj")
endif()

target_compile_definitions(coro-cloudstorage-fuse PRIVATE "_FILE_OFFSET_BITS=64")
