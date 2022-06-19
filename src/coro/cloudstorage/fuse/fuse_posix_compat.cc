#include "coro/cloudstorage/fuse/fuse_posix_compat.h"

#ifdef CORO_CLOUDSTORAGE_FUSE2

namespace coro::cloudstorage::fuse {

struct fuse_conn_info_opts* fuse_parse_conn_info_opts(struct fuse_args*) {
  return nullptr;
}

int fuse_parse_cmdline(struct fuse_args* args, struct fuse_cmdline_opts* opts) {
  return ::fuse_parse_cmdline(args, &opts->mountpoint, nullptr,
                              &opts->foreground);
}

void fuse_cmdline_help() {}

void fuse_lib_help(struct fuse_args*) {}

void fuse_lowlevel_version() {}

}  // namespace coro::cloudstorage::fuse

#endif
