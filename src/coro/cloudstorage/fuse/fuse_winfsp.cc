#include "coro/cloudstorage/fuse/fuse_winfsp.h"

#include <winfsp/winfsp.h>

#undef CreateDirectory
#undef CreateFile

#include <future>
#include <iostream>
#include <optional>
#include <string>

#include "coro/cloudstorage/fuse/filesystem_context.h"
#include "coro/cloudstorage/fuse/filesystem_provider.h"
#include "coro/cloudstorage/fuse/fuse_winfsp_context.h"
#include "coro/cloudstorage/util/abstract_cloud_provider.h"
#include "coro/cloudstorage/util/cloud_factory_context.h"
#include "coro/cloudstorage/util/random_number_generator.h"

namespace coro::cloudstorage::fuse {

namespace {

using ::coro::Task;
using ::coro::cloudstorage::CloudException;
using ::coro::cloudstorage::util::AbstractCloudProvider;
using ::coro::cloudstorage::util::AccountManagerHandler;
using ::coro::cloudstorage::util::AuthTokenManager;
using ::coro::cloudstorage::util::CloudFactoryContext;
using ::coro::cloudstorage::util::CloudProviderAccount;
using ::coro::cloudstorage::util::SettingsManager;
using ::coro::cloudstorage::util::StrCat;
using ::coro::cloudstorage::util::TimingOutCloudProvider;
using ::coro::util::AtScopeExit;
using ::coro::util::EventBaseDeleter;
using ::coro::util::EventLoop;
using ::coro::util::ThreadPool;

class WinFspServiceContext {
 public:
  WinFspServiceContext()
      : event_loop_thread_(&event_loop_), fs_context_(this) {}

  WinFspServiceContext(const WinFspServiceContext&) = delete;
  WinFspServiceContext(WinFspServiceContext&&) = delete;
  WinFspServiceContext& operator=(const WinFspServiceContext&) = delete;
  WinFspServiceContext& operator=(WinFspServiceContext&&) = delete;

 private:
  class FileSystemContext;

  using HttpT = http::CacheHttp;

  struct CloudProviderAccountListener {
    void OnCreate(CloudProviderAccount* account);
    Task<> OnDestroy(CloudProviderAccount* account);

    FileSystemContext* context;
  };

  class FileProvider {
   public:
    FileProvider(AbstractCloudProvider* provider, const EventLoop* event_loop,
                 ThreadPool* thread_pool, const wchar_t* mountpoint,
                 const wchar_t* prefix)
        : id_(reinterpret_cast<intptr_t>(provider)),
          provider_(std::make_unique<TimingOutCloudProvider>(event_loop, 10000,
                                                             provider)),
          fs_provider_(provider_.get(), thread_pool,
                       FileSystemProviderConfig()),
          context_(event_loop, &fs_provider_, mountpoint, prefix) {}

    intptr_t GetId() const { return id_; }

   private:
    intptr_t id_;
    std::unique_ptr<AbstractCloudProvider> provider_;
    FileSystemProvider fs_provider_;
    WinFspContext context_;
  };

  class FileSystemContext {
   public:
    FileSystemContext(WinFspServiceContext* context)
        : context_(&context->event_loop_),
          http_server_(&context->event_loop_,
                       SettingsManager(AuthTokenManager(context_.factory()))
                           .GetHttpServerConfig(),
                       context_.factory(), context_.thumbnail_generator(),
                       CloudProviderAccountListener{this},
                       SettingsManager(AuthTokenManager(context_.factory()))) {}

    FileSystemContext(const FileSystemContext&) = delete;
    FileSystemContext(FileSystemContext&&) = delete;
    FileSystemContext& operator=(const FileSystemContext&) = delete;
    FileSystemContext& operator=(FileSystemContext&&) = delete;

    ThreadPool* thread_pool() { return context_.thread_pool(); }
    const EventLoop* event_loop() { return context_.event_loop(); }

    Task<> Quit() { return http_server_.Quit(); }

   private:
    friend struct CloudProviderAccountListener;

    CloudFactoryContext context_;
    std::mutex mutex_;
    std::list<FileProvider> contexts_;
    coro::http::HttpServer<AccountManagerHandler> http_server_;
  };

  class EventLoopThread {
   public:
    EventLoopThread(EventLoop* event_loop)
        : event_loop_(event_loop),
          event_loop_thread_(std::async(std::launch::async, [&] { Main(); })) {}

    ~EventLoopThread() {
      event_loop_->ExitLoop();
      event_loop_thread_.get();
    }

   private:
    void Main() {
      try {
        coro::util::SetThreadName("event-loop");
        event_loop_->EnterLoop(coro::util::EventLoopType::NoExitOnEmpty);
      } catch (...) {
      }
    }

    EventLoop* event_loop_;
    std::future<void> event_loop_thread_;
  };

  class ContextWrapper : public std::optional<FileSystemContext> {
   public:
    ContextWrapper(WinFspServiceContext* context) : context_(context) {
      context_->event_loop_.Do([&] { emplace(context); });
    }

    ~ContextWrapper() {
      context_->event_loop_.Do([&]() -> Task<> {
        co_await(*this)->Quit();
        reset();
      });
    }

   private:
    WinFspServiceContext* context_;
  };

  EventLoop event_loop_;
  EventLoopThread event_loop_thread_;
  ContextWrapper fs_context_;
};

std::wstring ToWideString(std::string_view input) {
  int length = MultiByteToWideChar(
      CP_UTF8, 0, input.data(), static_cast<int>(input.length()), nullptr, 0);
  std::wstring buffer(length, 0);
  MultiByteToWideChar(CP_UTF8, 0, input.data(),
                      static_cast<int>(input.length()), buffer.data(),
                      static_cast<int>(buffer.length()));
  return buffer;
}

void WinFspServiceContext::CloudProviderAccountListener::OnCreate(
    CloudProviderAccount* account) {
  std::unique_lock lock{context->mutex_};
  context->contexts_.emplace_back(
      &account->provider(), context->event_loop(), context->thread_pool(),
      nullptr,
      ToWideString(
          util::StrCat("\\", account->type(), "\\", account->username()))
          .c_str());
  std::cerr << "CREATE " << account->id() << "\n";
}

Task<> WinFspServiceContext::CloudProviderAccountListener::OnDestroy(
    CloudProviderAccount* account) {
  co_await context->thread_pool()->Do([&] {
    std::unique_lock lock{context->mutex_};
    auto& contexts = context->contexts_;
    auto it = std::find_if(
        contexts.begin(), contexts.end(), [&](const auto& provider) {
          return provider.GetId() ==
                 reinterpret_cast<intptr_t>(&account->provider());
        });
    if (it != contexts.end()) {
      contexts.erase(it);
    }
  });
  std::cerr << "DESTROY " << account->id() << "\n";
}

}  // namespace

NTSTATUS SvcStart(FSP_SERVICE* service, ULONG argc, PWSTR* argv) {
  try {
    if (argc > 2) {
      return STATUS_INVALID_PARAMETER;
    }
    service->UserContext = new WinFspServiceContext;
    return STATUS_SUCCESS;
  } catch (const FileSystemException& e) {
    service->UserContext = nullptr;
    std::cerr << "FILESYSTEM EXCEPTION " << e.what() << "\n";
    FspServiceSetExitCode(service, e.status());
    return e.status();
  } catch (const std::exception& e) {
    service->UserContext = nullptr;
    std::cerr << "ERROR " << e.what() << "\n";
    FspServiceSetExitCode(service, STATUS_INVALID_DEVICE_REQUEST);
    return STATUS_INVALID_DEVICE_REQUEST;
  }
}

NTSTATUS SvcStop(FSP_SERVICE* service) {
  delete reinterpret_cast<WinFspServiceContext*>(service->UserContext);
  return STATUS_SUCCESS;
}

}  // namespace coro::cloudstorage::fuse
