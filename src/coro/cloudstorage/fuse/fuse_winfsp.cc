#include "fuse_winfsp.h"

#include <coro/cloudstorage/fuse/auth_data.h>
#include <coro/cloudstorage/fuse/filesystem_context.h>
#include <coro/cloudstorage/fuse/filesystem_provider.h>
#include <coro/cloudstorage/fuse/fuse_winfsp_context.h>
#include <coro/cloudstorage/util/abstract_cloud_provider.h>
#include <event2/thread.h>
#include <winfsp/winfsp.h>

#include <future>
#include <iostream>
#include <optional>
#include <string>

namespace coro::cloudstorage::fuse {

namespace {

using ::coro::Task;
using ::coro::cloudstorage::CloudException;
using ::coro::cloudstorage::util::AbstractCloudProvider;
using ::coro::util::AtScopeExit;
using ::coro::util::EventBaseDeleter;

class WinFspServiceContext {
 public:
  WinFspServiceContext()
      : event_base_([] {
          evthread_use_windows_threads();
          return event_base_new();
        }()),
        event_loop_thread_(event_base_.get()),
        event_loop_(event_base_.get()),
        fs_context_(this) {}

  WinFspServiceContext(const WinFspServiceContext&) = delete;
  WinFspServiceContext(WinFspServiceContext&&) = delete;
  WinFspServiceContext& operator=(const WinFspServiceContext&) = delete;
  WinFspServiceContext& operator=(WinFspServiceContext&&) = delete;

 private:
  using CloudProviderTypeList = FileSystemContext::CloudProviderTypeList;

  class FileSystemContext;

  using HttpT = http::CacheHttp<http::CurlHttp>;
  using ThumbnailGeneratorT =
      util::ThumbnailGenerator<coro::util::ThreadPool, coro::util::EventLoop>;
  using MuxerT = util::Muxer<coro::util::EventLoop, coro::util::ThreadPool>;
  using CloudFactoryT = CloudFactory<coro::util::EventLoop, HttpT,
                                     ThumbnailGeneratorT, MuxerT, AuthData>;

  using CloudProviderAccountT =
      coro::cloudstorage::util::CloudProviderAccount<CloudProviderTypeList,
                                                     CloudFactoryT>;

  struct CloudProviderAccountListener {
    void OnCreate(CloudProviderAccountT* account);
    Task<> OnDestroy(CloudProviderAccountT* account);

    FileSystemContext* context;
  };

  using AccountManagerHandlerT =
      util::AccountManagerHandler<CloudProviderTypeList, CloudFactoryT,
                                  ThumbnailGeneratorT,
                                  CloudProviderAccountListener>;

  class FileProvider {
   public:
    template <typename CloudProvider>
    FileProvider(CloudProvider* provider, coro::util::EventLoop* event_loop,
                 coro::util::ThreadPool* thread_pool, const wchar_t* mountpoint,
                 const wchar_t* prefix)
        : abstract_provider_(
              std::make_unique<
                  AbstractCloudProvider::CloudProviderImpl<CloudProvider>>(
                  provider)),
          provider_(event_loop, 10000, abstract_provider_.get()),
          fs_provider_(&provider_, event_loop, thread_pool,
                       FileSystemProviderConfig()),
          context_(event_loop, &fs_provider_, mountpoint, prefix) {}

    intptr_t GetId() const { return abstract_provider_->GetId(); }

   private:
    using CloudProviderT = util::TimingOutCloudProvider<
        AbstractCloudProvider::CloudProvider>::CloudProvider;

    std::unique_ptr<AbstractCloudProvider::CloudProvider> abstract_provider_;
    CloudProviderT provider_;
    FileSystemProvider<CloudProviderT> fs_provider_;
    WinFspContext<FileSystemProvider<CloudProviderT>> context_;
  };

  class FileSystemContext {
   public:
    FileSystemContext(WinFspServiceContext* context)
        : event_loop_(context->event_base_.get()),
          thread_pool_(event_loop_),
          http_(http::CacheHttpConfig{}, context->event_base_.get()),
          thumbnail_generator_(&thread_pool_, &event_loop_),
          muxer_(&event_loop_, &thread_pool_),
          factory_(event_loop_, http_, thumbnail_generator_, muxer_),
          http_server_(
              context->event_base_.get(),
              http::HttpServerConfig{.address = "127.0.0.1", .port = 12345},
              factory_, thumbnail_generator_,
              CloudProviderAccountListener{this}) {}

    FileSystemContext(const FileSystemContext&) = delete;
    FileSystemContext(FileSystemContext&&) = delete;
    FileSystemContext& operator=(const FileSystemContext&) = delete;
    FileSystemContext& operator=(FileSystemContext&&) = delete;

    Task<> Quit() { return http_server_.Quit(); }

   private:
    friend struct CloudProviderAccountListener;

    coro::util::EventLoop event_loop_;
    coro::util::ThreadPool thread_pool_;
    HttpT http_;
    ThumbnailGeneratorT thumbnail_generator_;
    MuxerT muxer_;
    CloudFactoryT factory_;
    std::mutex mutex_;
    std::list<FileProvider> contexts_;
    coro::http::HttpServer<AccountManagerHandlerT> http_server_;
  };

  class EventLoopThread {
   public:
    EventLoopThread(event_base* event_base)
        : event_base_(event_base),
          event_loop_thread_(std::async(std::launch::async, [&] { Main(); })) {}

    ~EventLoopThread() {
      event_base_loopexit(event_base_, nullptr);
      event_loop_thread_.get();
    }

   private:
    void Main() {
      try {
        coro::util::SetThreadName("event-loop");
        if (event_base_loop(event_base_, EVLOOP_NO_EXIT_ON_EMPTY) == -1) {
          throw std::runtime_error("event_base_dispatch error");
        }
      } catch (...) {
      }
    }

    event_base* event_base_;
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

  std::unique_ptr<event_base, EventBaseDeleter> event_base_;
  EventLoopThread event_loop_thread_;
  coro::util::EventLoop event_loop_;
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
    CloudProviderAccountT* account) {
  std::visit(
      [&]<typename CloudProvider>(CloudProvider& p) {
        std::unique_lock lock{context->mutex_};
        context->contexts_.emplace_back(
            &p, &context->event_loop_, &context->thread_pool_, nullptr,
            ToWideString(util::StrCat("\\", CloudProvider::Type::kId, "\\",
                                      account->username()))
                .c_str());
      },
      account->provider());
  std::cerr << "CREATE " << account->GetId() << "\n";
}

Task<> WinFspServiceContext::CloudProviderAccountListener::OnDestroy(
    CloudProviderAccountT* account) {
  co_await std::visit(
      [&]<typename CloudProvider>(const CloudProvider& p) -> Task<> {
        co_await context->thread_pool_.Do([&] {
          std::unique_lock lock{context->mutex_};
          auto& contexts = context->contexts_;
          auto it = std::find_if(
              contexts.begin(), contexts.end(), [&](const auto& provider) {
                return provider.GetId() == reinterpret_cast<intptr_t>(&p);
              });
          if (it != contexts.end()) {
            contexts.erase(it);
          }
        });
      },
      account->provider());
  std::cerr << "DESTROY " << account->GetId() << "\n";
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
