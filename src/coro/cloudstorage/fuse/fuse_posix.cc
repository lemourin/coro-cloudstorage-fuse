#include "coro/cloudstorage/fuse/fuse_posix.h"

#include <fuse.h>
#include <fuse_lowlevel.h>

#include <csignal>
#include <iostream>
#include <memory>

#include "coro/cloudstorage/fuse/filesystem_context.h"
#include "coro/cloudstorage/fuse/filesystem_provider.h"
#include "coro/cloudstorage/fuse/fuse_posix_context.h"
#include "coro/util/raii_utils.h"

namespace coro::cloudstorage::fuse {

namespace {

using ::coro::util::AtScopeExit;

constexpr std::array<int, 2> kHandledSignals = {SIGINT, SIGTERM};

struct FreeDeleter {
  template <typename T>
  void operator()(T* d) const {
    free(d);  // NOLINT
  }
};

struct EventContext {
  stdx::stop_source stop_source;
  FusePosixContext* context;
};

void CheckEvent(int d) {
  if (d != 0) {
    throw RuntimeError("libevent error");
  }
}

void OnSignal(evutil_socket_t, short, void* d) {
  auto* context = reinterpret_cast<EventContext*>(d);
  context->stop_source.request_stop();
  if (context->context) {
    context->context->Quit();
  }
}

Task<int> CoRun(int argc, char** argv, const coro::util::EventLoop* event_loop,
                FileSystemContext* fs_context) {
  fuse_args args = FUSE_ARGS_INIT(argc, argv);
  auto fuse_args_guard = AtScopeExit([&] { fuse_opt_free_args(&args); });
  std::unique_ptr<fuse_conn_info_opts, FreeDeleter> conn_opts(
      fuse_parse_conn_info_opts(&args));
  fuse_cmdline_opts options{};
  if (fuse_parse_cmdline(&args, &options) != 0) {
    co_return -1;
  }
  auto options_guard = AtScopeExit([&] {
    free(options.mountpoint);  // NOLINT
  });
  if (options.show_help) {
    std::cerr << "Please visit " CORO_CLOUDSTORAGE_REDIRECT_URI
                 " to add accounts while the program is running."
              << std::endl
              << std::endl;
    std::cerr << "Options for libfuse:" << std::endl;
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
    std::array<event, kHandledSignals.size()> signal_event = {};
    auto scope_guard = AtScopeExit([&] {
      for (event& event : signal_event) {
        event_del(&event);
      }
    });
    EventContext event_context{};
    for (size_t i = 0; i < signal_event.size(); i++) {
      CheckEvent(event_assign(
          &signal_event[i],
          reinterpret_cast<event_base*>(GetEventLoop(*event_loop)),
          kHandledSignals[i], EV_SIGNAL, OnSignal, &event_context));
      CheckEvent(event_add(&signal_event[i], nullptr));
    }
    auto http_server = fs_context->CreateHttpServer();
    std::unique_ptr<FusePosixContext> context;
    int status = 0;
    try {
      context = co_await FusePosixContext::Create(
          event_loop, &fs_context->fs(), &args, &options, conn_opts.get(),
          event_context.stop_source.get_token());
      event_context.context = context.get();
      if (fuse_daemonize(options.foreground) != 0) {
        throw RuntimeError("fuse_daemonize failed");
      }
      co_await context->Run();
    } catch (const std::exception& e) {
      std::cerr << "EXCEPTION " << e.what() << "\n";
      status = -1;
    }
    co_await http_server.Quit();
    co_return status;
  } catch (const std::exception& e) {
    std::cerr << "EXCEPTION " << e.what() << "\n";
    co_return -1;
  }
}

}  // namespace

int Run(int argc, char** argv) {
  coro::util::EventLoop event_loop;
  FileSystemContext fs_context(&event_loop);
  int status = 0;
  coro::RunTask([&]() -> Task<> {
    status = co_await CoRun(argc, argv, &event_loop, &fs_context);
  });
  event_loop.EnterLoop();
  return status;
}

}  // namespace coro::cloudstorage::fuse
