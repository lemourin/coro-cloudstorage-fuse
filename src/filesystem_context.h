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

#include <future>

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
    std::string id;
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
          .id = std::visit(
              [](const auto& d) {
                std::stringstream sstream;
                sstream << d.id;
                return std::move(sstream).str();
              },
              item),
          .name = std::visit([](const auto& d) { return d.name; }, item),
          .is_directory = std::visit(
              [](const auto& d) {
                return IsDirectory<decltype(d), CloudProviderT>;
              },
              item),
          .timestamp = std::visit(
              [](const auto& d) { return CloudProviderT::GetTimestamp(d); },
              item),
          .size = std::visit(
              [](const auto& d) { return CloudProviderT::GetSize(d); }, item)};
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
      std::optional<Generator<std::string>::iterator> it;
      std::string chunk;
      int64_t current_offset;
      bool pending;
    };
    struct QueuedRead {
      Promise<void> awaiter;
      int64_t offset;
      int64_t size;
    };
    mutable std::optional<CurrentRead> current_read;
    mutable std::vector<QueuedRead*> queued_reads;
  };

  struct PageData {
    std::vector<FileContext> items;
    std::optional<std::string> next_page_token;
  };

  explicit FileSystemContext(event_base*);
  ~FileSystemContext();

  FileSystemContext(const FileSystemContext&) = delete;
  FileSystemContext(FileSystemContext&&) = delete;
  FileSystemContext& operator=(const FileSystemContext&) = delete;
  FileSystemContext& operator=(FileSystemContext&&) = delete;

  template <typename F>
  void RunOnEventLoop(F func) {
    F* data = new F(std::move(func));
    if (event_base_once(
            event_base_, -1, EV_TIMEOUT,
            [](evutil_socket_t, short, void* d) {
              Invoke([func = reinterpret_cast<F*>(d)]() -> Task<> {
                co_await (*func)();
                delete func;
              });
            },
            data, nullptr) != 0) {
      delete data;
      throw std::runtime_error("can't run on event loop");
    }
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
  Task<FileContext> GetFileContext(std::string path, stdx::stop_token) const;
  Generator<std::vector<FileContext>> ReadDirectory(const FileContext& context,
                                                    stdx::stop_token) const;
  Task<PageData> ReadDirectoryPage(const FileContext& context,
                                   std::optional<std::string> page_token,
                                   stdx::stop_token) const;
  Task<VolumeData> GetVolumeData(stdx::stop_token) const;
  Task<std::string> Read(const FileContext&, int64_t offset, int64_t size,
                         stdx::stop_token) const;
  Task<FileContext> Rename(const FileContext& item, std::string_view new_name,
                           stdx::stop_token);
  Task<FileContext> Move(const FileContext& source,
                         const FileContext& destination, stdx::stop_token);
  Task<FileContext> CreateDirectory(const FileContext& item,
                                    std::string_view name, stdx::stop_token);
  Task<> Remove(const FileContext&, stdx::stop_token);

  void Quit();
  void Cancel();

 private:
  std::shared_ptr<CloudProviderAccount> GetAccount(std::string_view name) const;
  Task<> Main();

  struct GetDirectoryPage {
    template <typename T>
    Task<PageData> operator()(const T&) const;
    std::optional<std::string> page_token;
    stdx::stop_token stop_token;
  };

  coro::Promise<void> quit_;
  event_base* event_base_;
  coro::util::EventLoop event_loop_;
  std::set<std::shared_ptr<CloudProviderAccount>> accounts_;
  bool quit_called_ = false;
  Http http_;
};

extern template class FileSystemContext<CloudProviders>;

}  // namespace internal

using FileSystemContext = internal::FileSystemContext<internal::CloudProviders>;

}  // namespace coro::cloudstorage

#endif  // FILESYSTEM_CONTEXT_H