#include <windows.h>

#include <csignal>

#include "fuse_winfsp.h"

int main() {
#ifdef _WIN32
  WORD version_requested = MAKEWORD(2, 2);
  WSADATA wsa_data;

  (void)WSAStartup(version_requested, &wsa_data);
#endif

#ifdef SIGPIPE
  signal(SIGPIPE, SIG_IGN);
#endif

  return coro::cloudstorage::fuse::RunWinFSP();
}