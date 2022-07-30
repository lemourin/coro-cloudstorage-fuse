#include "coro/cloudstorage/fuse/fuse_winfsp.h"

#include <winfsp/winfsp.h>

#undef CreateDirectory
#undef CreateFile

#include <deque>
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
using ::coro::util::EventLoop;
using ::coro::util::ThreadPool;

std::wstring ToWideString(std::string_view input) {
  int length = MultiByteToWideChar(
      CP_UTF8, 0, input.data(), static_cast<int>(input.length()), nullptr, 0);
  std::wstring buffer(length, 0);
  MultiByteToWideChar(CP_UTF8, 0, input.data(),
                      static_cast<int>(input.length()), buffer.data(),
                      static_cast<int>(buffer.length()));
  return buffer;
}

class WinFspServiceContext {
 public:
  WinFspServiceContext()
      : event_loop_thread_(std::async(std::launch::async, [&] {
          try {
            coro::util::SetThreadName("event-loop");
            event_loop_.EnterLoop(coro::util::EventLoopType::NoExitOnEmpty);
          } catch (...) {
          }
        })) {
    event_loop_.Do([&] { fs_context_.emplace(this); });
  }

  WinFspServiceContext(const WinFspServiceContext&) = delete;
  WinFspServiceContext(WinFspServiceContext&&) = delete;
  WinFspServiceContext& operator=(const WinFspServiceContext&) = delete;
  WinFspServiceContext& operator=(WinFspServiceContext&&) = delete;

  ~WinFspServiceContext() {
    event_loop_.Do([&]() -> Task<> { co_await fs_context_->Quit(); });
    event_loop_.ExitLoop();
    event_loop_thread_.get();
  }

 private:
  class FileSystemContext;

  using HttpT = http::CacheHttp;

  struct CloudProviderAccountListener {
    void OnCreate(std::shared_ptr<CloudProviderAccount> account);
    void OnDestroy(std::shared_ptr<CloudProviderAccount> account);

    FileSystemContext* context;
  };

  class FileProvider {
   public:
    FileProvider(std::shared_ptr<AbstractCloudProvider> provider,
                 const EventLoop* event_loop, ThreadPool* thread_pool,
                 const wchar_t* mountpoint, const wchar_t* prefix)
        : base_provider_(std::move(provider)),
          provider_(event_loop, 10000, base_provider_.get()),
          fs_provider_(&provider_, thread_pool, FileSystemProviderConfig()),
          context_(event_loop, &fs_provider_, mountpoint, prefix) {}

    intptr_t GetId() const {
      return reinterpret_cast<intptr_t>(base_provider_.get());
    }

   private:
    std::shared_ptr<AbstractCloudProvider> base_provider_;
    TimingOutCloudProvider provider_;
    FileSystemProvider fs_provider_;
    WinFspContext context_;
  };

  class FileSystemContext {
   public:
    FileSystemContext(WinFspServiceContext* context)
        : event_loop_(&context->event_loop_),
          context_(&context->event_loop_),
          background_thread_(
              std::async(std::launch::async, [&] { RunBackgroundThread(); })),
          http_server_(
              context_.CreateHttpServer(CloudProviderAccountListener{this})) {}

    FileSystemContext(const FileSystemContext&) = delete;
    FileSystemContext(FileSystemContext&&) = delete;
    FileSystemContext& operator=(const FileSystemContext&) = delete;
    FileSystemContext& operator=(FileSystemContext&&) = delete;

    ~FileSystemContext() {
      {
        std::unique_lock lock{mutex_};
        quit_ = true;
        condition_variable_.notify_one();
      }
      background_thread_.get();
    }

    ThreadPool* thread_pool() { return context_.thread_pool(); }
    const EventLoop* event_loop() { return event_loop_; }

    void AddAccount(std::shared_ptr<CloudProviderAccount> account) {
      std::unique_lock lock{mutex_};
      tasks_.emplace_back([this, account = std::move(account)] {
        std::unique_lock lock{mutex_};
        contexts_.emplace_back(
            account->provider(), event_loop(), thread_pool(), nullptr,
            ToWideString(
                util::StrCat("\\", account->type(), "\\", account->username()))
                .c_str());
      });
      condition_variable_.notify_one();
    }

    void RemoveAccount(std::shared_ptr<CloudProviderAccount> account) {
      std::unique_lock lock{mutex_};
      tasks_.emplace_back([this, account = std::move(account)] {
        std::unique_lock lock{mutex_};
        auto it = std::find_if(
            contexts_.begin(), contexts_.end(), [&](const auto& provider) {
              return provider.GetId() ==
                     reinterpret_cast<intptr_t>(account->provider().get());
            });
        if (it != contexts_.end()) {
          contexts_.erase(it);
        }
      });
      condition_variable_.notify_one();
    }

    Task<> Quit() { return http_server_.Quit(); }

   private:
    friend struct CloudProviderAccountListener;

    void RunBackgroundThread() {
      coro::util::SetThreadName("background-thread");

      while (true) {
        std::unique_lock lock{mutex_};
        condition_variable_.wait(lock,
                                 [&] { return quit_ || !tasks_.empty(); });
        while (!tasks_.empty()) {
          auto task = std::move(*tasks_.begin());
          tasks_.pop_front();
          lock.unlock();
          std::move(task)();
          lock.lock();
        }
        if (quit_) {
          break;
        }
      }
    }

    const EventLoop* event_loop_;
    CloudFactoryContext context_;
    bool quit_ = false;
    std::mutex mutex_;
    std::condition_variable condition_variable_;
    std::deque<stdx::any_invocable<void() &&>> tasks_;
    std::list<FileProvider> contexts_;
    std::future<void> background_thread_;
    coro::http::HttpServer<AccountManagerHandler> http_server_;
  };

  EventLoop event_loop_;
  std::optional<FileSystemContext> fs_context_;
  std::future<void> event_loop_thread_;
};

void WinFspServiceContext::CloudProviderAccountListener::OnCreate(
    std::shared_ptr<CloudProviderAccount> account) {
  std::cerr << "CREATE [" << account->type() << "] " << account->username()
            << '\n';
  context->AddAccount(std::move(account));
}

void WinFspServiceContext::CloudProviderAccountListener::OnDestroy(
    std::shared_ptr<CloudProviderAccount> account) {
  std::cerr << "DESTROY [" << account->type() << "] " << account->username()
            << '\n';
  context->RemoveAccount(std::move(account));
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
