#ifndef CORO_CLOUDSTORAGE_FUSE_FUSE_POSIX_COMPAT_H
#define CORO_CLOUDSTORAGE_FUSE_FUSE_POSIX_COMPAT_H

#include <fuse_lowlevel.h>

namespace coro::cloudstorage::fuse {

struct fuse_cmdline_opts {
  char* mountpoint;
  bool show_help;
  bool show_version;
  int foreground;
};

struct fuse_conn_info_opts;

struct fuse_conn_info_opts* fuse_parse_conn_info_opts(struct fuse_args*);

int fuse_parse_cmdline(struct fuse_args* args, struct fuse_cmdline_opts* opts);

void fuse_cmdline_help();

void fuse_lib_help(struct fuse_args*);

void fuse_lowlevel_version();

}  // namespace coro::cloudstorage::fuse

#endif  // CORO_CLOUDSTORAGE_FUSE_FUSE_POSIX_COMPAT_H
