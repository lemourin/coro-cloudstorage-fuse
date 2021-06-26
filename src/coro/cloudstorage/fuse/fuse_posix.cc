#include "fuse_posix.h"

#include <coro/cloudstorage/fuse/filesystem_context.h>
#include <coro/cloudstorage/fuse/filesystem_provider.h>
#include <coro/cloudstorage/fuse/fuse_posix_context.h>
#include <coro/util/raii_utils.h>
#include <event2/thread.h>
#include <fuse.h>
#include <fuse_lowlevel.h>

#include <csignal>
#include <iostream>

namespace coro::cloudstorage::fuse {

namespace {

using ::coro::util::AtScopeExit;
using ::coro::util::EventBaseDeleter;

using FuseContext = FusePosixContext<FileSystemContext::FileSystemProviderT>;

constexpr int kHandledSignals[] = {SIGINT, SIGTERM};

struct FreeDeleter {
  template <typename T>
  void operator()(T* d) const {
    free(d);
  }
};

struct EventContext {
  stdx::stop_source stop_source;
  FuseContext* context;
};

void CheckEvent(int d) {
  if (d != 0) {
    throw std::runtime_error("libevent error");
  }
}

void OnSignal(evutil_socket_t fd, short, void* d) {
  auto* context = reinterpret_cast<EventContext*>(d);
  context->stop_source.request_stop();
  if (context->context) {
    context->context->Quit();
  }
}

Task<int> CoRun(int argc, char** argv, event_base* event_base) {
  fuse_args args = FUSE_ARGS_INIT(argc, argv);
  auto fuse_args_guard = AtScopeExit([&] { fuse_opt_free_args(&args); });
  std::unique_ptr<fuse_conn_info_opts, FreeDeleter> conn_opts(
      fuse_parse_conn_info_opts(&args));
  fuse_cmdline_opts options;
  if (fuse_parse_cmdline(&args, &options) != 0) {
    co_return -1;
  }
  auto options_guard = AtScopeExit([&] { free(options.mountpoint); });
  if (options.show_help) {
    fuse_cmdline_help();
    fuse_lib_help(&args);
    co_return 0;
  }
  if (options.show_version) {
    fuse_lowlevel_version();
    co_return 0;
  }
  if (!options.mountpoint) {
    std::cerr << "Mountpoint not specified.\n";
    co_return -1;
  }
  try {
    event signal_event[sizeof(kHandledSignals) / sizeof(kHandledSignals[0])] =
        {};
    auto scope_guard = AtScopeExit([&] {
      for (event& event : signal_event) {
        event_del(&event);
      }
    });
    EventContext event_context{};
    for (size_t i = 0; i < sizeof(kHandledSignals) / sizeof(kHandledSignals[0]);
         i++) {
      CheckEvent(event_assign(&signal_event[i], event_base, kHandledSignals[i],
                              EV_SIGNAL, OnSignal, &event_context));
      CheckEvent(event_add(&signal_event[i], nullptr));
    }
    FileSystemContext fs_context(event_base);
    auto context = co_await FuseContext::Create(
        event_base, &fs_context.fs(), &args, &options, conn_opts.get(),
        event_context.stop_source.get_token());
    event_context.context = context.get();
    if (fuse_daemonize(options.foreground) != 0) {
      throw std::runtime_error("fuse_daemonize failed");
    }
    co_await context->Run();
    co_await fs_context.Quit();
    co_return 0;
  } catch (const std::exception& e) {
    std::cerr << "EXCEPTION " << e.what() << "\n";
    co_return -1;
  }
}

}  // namespace

int Run(int argc, char** argv) {
  std::unique_ptr<event_base, EventBaseDeleter> event_base([] {
    evthread_use_pthreads();
    return event_base_new();
  }());
  int status = 0;
  coro::RunTask([&]() -> Task<> {
    status = co_await CoRun(argc, argv, event_base.get());
  });
  if (event_base_dispatch(event_base.get()) != 1) {
    throw std::runtime_error("event_base_dispatch failed");
  }
  return status;
}

}  // namespace coro::cloudstorage::fuse