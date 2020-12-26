#ifndef FILESYSTEM_CONTEXT_H
#define FILESYSTEM_CONTEXT_H

#include <coro/cloudstorage/cloud_exception.h>
#include <coro/cloudstorage/cloud_factory.h>
#include <coro/cloudstorage/util/account_manager_handler.h>
#include <coro/http/cache_http.h>
#include <coro/http/curl_http.h>
#include <coro/http/http_server.h>
#include <coro/semaphore.h>
#include <coro/task.h>
#include <coro/util/event_loop.h>
#include <coro/util/type_list.h>
#include <event.h>
#include <event2/thread.h>

#include <thread>

namespace coro::cloudstorage {

template <typename>
class FileSystemContext;

template <typename... CloudProvider>
class FileSystemContext<::coro::util::TypeList<CloudProvider...>> {
 public:
  static constexpr std::string_view kTokenFile = "access-token.json";
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
    void OnCreate(CloudProviderAccount* d) {
      context->accounts_.insert(
          std::shared_ptr<CloudProviderAccount>(d, [](auto) {}));
      std::cerr << "CREATED " << d->id << "\n";
    }
    void OnDestroy(CloudProviderAccount* d) {
      context->accounts_.erase(
          std::shared_ptr<CloudProviderAccount>(d, [](auto) {}));
      std::cerr << "REMOVED " << d->id << "\n";
    }

    FileSystemContext* context;
  };

  struct VolumeData {
    int64_t space_used;
    std::optional<int64_t> space_total;
  };

  struct GenericItem {
    std::string name;
    bool is_directory;
    std::optional<int64_t> size;
  };

  template <typename T>
  struct Item {
    using CloudProvider = T;

    Item(std::weak_ptr<CloudProviderAccount> account,
         typename CloudProvider::Item item)
        : account(std::move(account)), item(std::move(item)) {}

    CloudProvider* provider() const {
      auto acc = account.lock();
      if (!acc) {
        throw CloudException(CloudException::Type::kNotFound);
      }
      return &std::get<CloudProvider>(acc->provider);
    }

    auto GetGenericItem() const {
      return GenericItem{
          .name = std::visit([](const auto& d) { return d.name; }, item),
          .is_directory =
              std::holds_alternative<typename CloudProvider::Directory>(item),
          .size = std::visit(
              [](const auto& d) {
                if constexpr (std::is_same_v<std::remove_cvref_t<decltype(d)>,
                                             typename CloudProvider::File>) {
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

  template <typename CloudProvider>
  using ItemT = Item<
      typename CloudProviderAccount::template CloudProviderT<CloudProvider>>;

  using FileContext = std::optional<std::variant<ItemT<CloudProvider>...>>;

  FileSystemContext()
      : event_loop_([] {
#ifdef WIN32
          evthread_use_windows_threads();
#else
          evthread_use_posix_threads();
#endif
          return event_base_new();
        }()),
        thread_([this] { Main(); }) {
  }

  FileSystemContext(const FileSystemContext&) = delete;
  FileSystemContext(FileSystemContext&&) = delete;
  FileSystemContext& operator()(const FileSystemContext&) = delete;
  FileSystemContext& operator()(FileSystemContext&&) = delete;

  ~FileSystemContext() {
    event_base_once(
        event_loop_.get(), -1, EV_TIMEOUT,
        [](evutil_socket_t, short, void* d) {
          reinterpret_cast<FileSystemContext*>(d)->quit_.resume();
        },
        this, nullptr);
    thread_.join();
  }

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

  static GenericItem GetGenericItem(const FileContext& ctx) {
    if (!ctx) {
      return GenericItem{.name = "root", .is_directory = true};
    }
    return std::visit([](const auto& d) { return d.GetGenericItem(); }, *ctx);
  }

  Task<FileContext> GetFileContext(std::string path) const {
    auto components = SplitString(path, '/');
    if (components.empty()) {
      co_return FileContext{};
    }
    auto account = GetAccount(*components.begin());
    std::string provider_path;
    for (size_t i = 1; i < components.size(); i++) {
      provider_path += "/" + components[i];
    }
    co_return co_await std::visit(
        [=](auto& d) -> Task<std::variant<ItemT<CloudProvider>...>> {
          using CloudProvider = std::remove_cvref_t<decltype(d)>;
          co_return Item<CloudProvider>(
              account, co_await d.GetItemByPath(provider_path));
        },
        account->provider);
  }

  Generator<std::vector<FileContext>> ReadDirectory(FileContext context) const {
    if (!context) {
      std::vector<FileContext> result;
      for (auto account : accounts_) {
        auto root = co_await std::visit(
            [](auto& provider)
                -> Task<std::variant<typename CloudProvider::Directory...>> {
              co_return co_await provider.GetRoot();
            },
            account->provider);
        std::visit([id = account->id](
                       auto& directory) { directory.name = std::move(id); },
                   root);
        result.emplace_back(std::make_optional(std::visit(
            [&](auto& provider) -> std::variant<ItemT<CloudProvider>...> {
              using CloudProviderT = std::remove_cvref_t<decltype(provider)>;
              return Item<CloudProviderT>(
                  account, std::get<typename CloudProviderT::Directory>(root));
            },
            account->provider)));
      }
      co_yield std::move(result);
      co_return;
    }
    Generator<std::vector<FileContext>> generator = std::visit(
        [](const auto& d) -> Generator<std::vector<FileContext>> {
          using CloudProviderT =
              typename std::remove_cvref_t<decltype(d)>::CloudProvider;
          FOR_CO_AWAIT(
              auto& page_data,
              d.provider()->ListDirectory(
                  std::get<typename CloudProviderT::Directory>(d.item)),
              {
                std::vector<FileContext> page;
                for (auto& item : page_data.items) {
                  page.emplace_back(
                      Item<CloudProviderT>(d.account, std::move(item)));
                }
                co_yield std::move(page);
              });
        },
        *context);

    FOR_CO_AWAIT(std::vector<FileContext> & page_data, generator,
                 { co_yield std::move(page_data); });
  }

  Task<VolumeData> GetVolumeData() const {
    using AnyTask = std::variant<Task<typename CloudProvider::GeneralData>...>;
    std::vector<AnyTask> tasks;
    for (const auto& account : accounts_) {
      tasks.emplace_back(std::visit(
          [](auto& provider) -> AnyTask { return provider.GetGeneralData(); },
          account->provider));
    }
    VolumeData total = {.space_used = 0, .space_total = 0};
    for (auto& task : tasks) {
      auto data = co_await std::visit(
          [&](auto& task) -> Task<VolumeData> {
            auto data = co_await task;
            co_return VolumeData{.space_used = data.space_used,
                                 .space_total = data.space_total};
          },
          task);
      total.space_used += data.space_used;
      if (data.space_total && total.space_total) {
        *total.space_total += *data.space_total;
      } else {
        total.space_total = std::nullopt;
        break;
      }
    }
    co_return total;
  }

 private:
  std::shared_ptr<CloudProviderAccount> GetAccount(
      std::string_view name) const {
    auto it = std::find_if(accounts_.begin(), accounts_.end(),
                           [name](auto d) { return d->id == name; });
    if (it == accounts_.end()) {
      throw CloudException(CloudException::Type::kNotFound);
    } else {
      return *it;
    }
  }

  void Main() {
    Invoke(CoMain(event_loop_.get()));
    event_base_dispatch(event_loop_.get());
  }

  Task<> CoMain(event_base* event_loop) {
    try {
      Http http{http::CurlHttp(event_loop)};
      CloudFactory cloud_factory(EventLoop(event_loop), http);
      http::HttpServer http_server(
          event_loop, {.address = "0.0.0.0", .port = 12345},
          AccountManagerHandlerT(
              cloud_factory, AccountListener{this},
              util::AuthTokenManager{.token_file = std::string(kTokenFile)}));
      co_await quit_;
      co_await http_server.Quit();
      co_return;
    } catch (const std::exception& exception) {
      std::cerr << "EXCEPTION: " << exception.what() << "\n";
    }
  }

  struct EventBaseDeleter {
    void operator()(event_base* event_loop) const {
      event_base_free(event_loop);
    }
  };

  template <typename T, typename C>
  static std::vector<T> SplitString(const T& string, C delim) {
    std::vector<T> result;
    T current;
    for (auto c : string) {
      if (c == delim) {
        if (!current.empty()) {
          result.emplace_back(std::move(current));
        }
        current.clear();
      } else {
        current += c;
      }
    }
    if (!current.empty()) {
      result.emplace_back(std::move(current));
    }
    return result;
  }

  coro::Semaphore quit_;
  std::unique_ptr<event_base, EventBaseDeleter> event_loop_;
  std::thread thread_;
  std::set<std::shared_ptr<CloudProviderAccount>> accounts_;
};

}  // namespace coro::cloudstorage

#endif  // FILESYSTEM_CONTEXT_H