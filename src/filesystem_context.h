#ifndef FILESYSTEM_CONTEXT_H
#define FILESYSTEM_CONTEXT_H

#include <coro/cloudstorage/cloud_exception.h>
#include <coro/cloudstorage/cloud_factory.h>
#include <coro/cloudstorage/cloud_provider.h>
#include <coro/cloudstorage/providers/dropbox.h>
#include <coro/cloudstorage/providers/google_drive.h>
#include <coro/cloudstorage/providers/mega.h>
#include <coro/cloudstorage/providers/one_drive.h>
#include <coro/cloudstorage/util/account_manager_handler.h>
#include <coro/http/cache_http.h>
#include <coro/http/curl_http.h>
#include <coro/promise.h>
#include <coro/stdx/concepts.h>
#include <coro/task.h>
#include <coro/util/event_loop.h>
#include <coro/util/type_list.h>
#include <event.h>
#include <event2/thread.h>

#include <future>
#include <thread>

namespace coro::cloudstorage {

namespace internal {

using CloudProviders =
    coro::util::TypeList<coro::cloudstorage::GoogleDrive,
                         coro::cloudstorage::Mega, coro::cloudstorage::OneDrive,
                         coro::cloudstorage::Dropbox>;

template <typename>
class FileSystemContext;

template <typename... CloudProvider>
class FileSystemContext<::coro::util::TypeList<CloudProvider...>> {
 public:
  static_assert(
      std::is_same_v<::coro::util::TypeList<CloudProvider...>, CloudProviders>);

  using Http = http::CacheHttp<http::CurlHttp>;
  using EventLoop = ::coro::util::EventLoop;

  struct AccountListener;

  using AccountManagerHandlerT =
      util::AccountManagerHandler<::coro::util::TypeList<CloudProvider...>,
                                  CloudFactory<EventLoop, Http>,
                                  AccountListener>;
  using CloudProviderAccount =
      typename AccountManagerHandlerT::CloudProviderAccount;

  struct AccountListener {
    void OnCreate(CloudProviderAccount*);
    void OnDestroy(CloudProviderAccount*);
    FileSystemContext* context;
  };

  struct VolumeData {
    int64_t space_used;
    std::optional<int64_t> space_total;
  };

  struct GenericItem {
    std::string name;
    bool is_directory;
    std::optional<int64_t> timestamp;
    std::optional<int64_t> size;
  };

  template <typename T>
  struct Item {
    using CloudProviderT = T;

    Item(std::weak_ptr<CloudProviderAccount> account, typename T::Item item)
        : account(std::move(account)), item(std::move(item)) {}

    T* provider() const {
      auto acc = account.lock();
      if (!acc) {
        throw CloudException(CloudException::Type::kNotFound);
      }
      return &std::get<T>(acc->provider);
    }

    auto GetGenericItem() const {
      return GenericItem{
          .name = std::visit([](const auto& d) { return d.name; }, item),
          .is_directory = std::holds_alternative<typename T::Directory>(item),
          .timestamp = std::visit(
              [](const auto& d) -> std::optional<int64_t> {
                if constexpr (HasTimestamp<decltype(d)>) {
                  return d.timestamp;
                } else {
                  return std::nullopt;
                }
              },
              item),
          .size = std::visit(
              [](const auto& d) {
                if constexpr (std::is_same_v<std::remove_cvref_t<decltype(d)>,
                                             typename T::File>) {
                  return d.size;
                } else {
                  return std::optional<int64_t>();
                }
              },
              item)};
    }

    std::weak_ptr<CloudProviderAccount> account;
    typename T::Item item;
  };

  template <typename T>
  using ItemT = Item<typename CloudProviderAccount::template CloudProviderT<T>>;

  struct FileContext {
    std::optional<std::variant<ItemT<CloudProvider>...>> item;
    struct CurrentRead {
      Generator<std::string> generator;
      Generator<std::string>::iterator it;
      std::string chunk;
      int64_t offset;
    };
    mutable std::optional<CurrentRead> current_read;
  };

  FileSystemContext();
  ~FileSystemContext();

  FileSystemContext(const FileSystemContext&) = delete;
  FileSystemContext(FileSystemContext&&) = delete;
  FileSystemContext& operator()(const FileSystemContext&) = delete;
  FileSystemContext& operator()(FileSystemContext&&) = delete;

  template <typename F>
  void RunOnEventLoop(F func) {
    F* data = new F(std::move(func));
    event_base_once(
        event_loop_.get(), -1, EV_TIMEOUT,
        [](evutil_socket_t, short, void* d) {
          Invoke([func = reinterpret_cast<F*>(d)]() -> Task<> {
            co_await (*func)();
            delete func;
          });
        },
        data, nullptr);
  }

  template <typename F>
  auto Do(F func) {
    using ResultType = decltype(func().await_resume());
    std::promise<ResultType> result;
    RunOnEventLoop([&result, &func]() -> Task<> {
      try {
        result.set_value(co_await func());
      } catch (const std::exception&) {
        result.set_exception(std::current_exception());
      }
    });
    return result.get_future().get();
  }

  static GenericItem GetGenericItem(const FileContext& ctx);
  Task<FileContext> GetFileContext(std::string path) const;
  Generator<std::vector<FileContext>> ReadDirectory(
      const FileContext& context) const;
  Task<VolumeData> GetVolumeData() const;
  Task<std::string> Read(const FileContext&, int64_t offset,
                         int64_t size) const;

 private:
  std::shared_ptr<CloudProviderAccount> GetAccount(std::string_view name) const;
  void Main();
  Task<> CoMain(event_base* event_loop);

  struct EventBaseDeleter {
    void operator()(event_base* event_loop) const {
      event_base_free(event_loop);
    }
  };

  struct GetDirectoryGenerator {
    template <typename T>
    Generator<std::vector<FileContext>> operator()(const T&) const;
  };

  std::promise<void> initialized_;
  coro::Promise<void> quit_;
  std::unique_ptr<event_base, EventBaseDeleter> event_loop_;
  std::future<void> thread_;
  std::set<std::shared_ptr<CloudProviderAccount>> accounts_;
};

extern template class FileSystemContext<CloudProviders>;

}  // namespace internal

using FileSystemContext = internal::FileSystemContext<internal::CloudProviders>;

}  // namespace coro::cloudstorage

#endif  // FILESYSTEM_CONTEXT_H