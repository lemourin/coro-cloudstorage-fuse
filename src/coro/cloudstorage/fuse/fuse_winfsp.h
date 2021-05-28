#ifndef FUSE_WINFSP
#define FUSE_WINFSP

// clang-format off
#include <winsock2.h>
#include <windows.h>
// clang-format on

#include <winfsp/winfsp.h>

namespace coro::cloudstorage::fuse {

NTSTATUS SvcStart(FSP_SERVICE* service, ULONG argc, PWSTR* argv);
NTSTATUS SvcStop(FSP_SERVICE* service);

}  // namespace coro::cloudstorage::fuse

#endif  // FUSE_WINFSP