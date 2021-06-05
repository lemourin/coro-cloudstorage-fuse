#ifndef FUSE_WINFSP
#define FUSE_WINFSP

#include <winfsp/winfsp.h>

namespace coro::cloudstorage::fuse {

NTSTATUS SvcStart(FSP_SERVICE* service, ULONG argc, PWSTR* argv);
NTSTATUS SvcStop(FSP_SERVICE* service);

}  // namespace coro::cloudstorage::fuse

#endif  // FUSE_WINFSP