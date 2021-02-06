#ifndef FILESYSTEM_CONTEXT_H
#define FILESYSTEM_CONTEXT_H

#include <coro/cloudstorage/abstract_cloud_provider.h>
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

class FileSystemContext {
 public:
  using Http = http::CacheHttp<http::CurlHttp>;
  using EventLoop = ::coro::util::EventLoop;

  struct AccountListener;

  // using CloudProviders = coro::util::TypeList<
  //    coro::cloudstorage::GoogleDrive, coro::cloudstorage::Mega,
  //    coro::cloudstorage::OneDrive, coro::cloudstorage::Dropbox>;
  using CloudProviders = coro::util::TypeList<coro::cloudstorage::Dropbox>;

  using AccountManagerHandlerT =
      util::AccountManagerHandler<CloudProviders, CloudFactory<EventLoop, Http>,
                                  AccountListener>;
  using CloudProviderAccount = AccountManagerHandlerT::CloudProviderAccount;

  struct AccountListener {
    void OnCreate(CloudProviderAccount*);
    void OnDestroy(CloudProviderAccount*);
    FileSystemContext* context;
  };

  struct VolumeData {
    int64_t space_used;
    std::optional<int64_t> space_total;
  };

  using AbstractCloudProvider = AccountManagerHandlerT::AbstractCloudProvider;
  using AbstractCloudProviderT = AbstractCloudProvider::CloudProvider;

  using GenericItem = AbstractCloudProvider::GenericItem;

  struct Item {
    Item(std::weak_ptr<CloudProviderAccount> account,
         AbstractCloudProviderT::Item item)
        : account(std::move(account)), item(std::move(item)) {}

    AbstractCloudProviderT provider() const;
    stdx::stop_token stop_token() const;
    GenericItem GetGenericItem() const;

    std::weak_ptr<CloudProviderAccount> account;
    AbstractCloudProviderT::Item item;
  };

  struct FileDeleter {
    void operator()(std::FILE* file) const {
      if (file) {
        fclose(file);
      }
    }
  };

  struct StopTokenData {
    stdx::stop_source stop_source;
    ::coro::util::StopTokenOr stop_token_or;
    StopTokenData(stdx::stop_token root_token)
        : stop_token_or(std::move(root_token), stop_source.get_token()) {}
    ~StopTokenData() { stop_source.request_stop(); }
  };

  struct CurrentRead {
    Generator<std::string> generator;
    std::optional<Generator<std::string>::iterator> it;
    std::string chunk;
    int64_t current_offset;
    bool pending;
    std::unique_ptr<StopTokenData> stop_token_data;
  };

  struct QueuedRead {
    Promise<void> awaiter;
    int64_t offset;
    int64_t size;
  };

  struct CurrentWrite {
    std::unique_ptr<std::FILE, FileDeleter> tmpfile;
    std::string new_name;
  };

  struct FileContext {
    std::optional<Item> item;
    std::optional<Item> parent;

    mutable std::optional<CurrentRead> current_read;
    mutable std::vector<QueuedRead*> queued_reads;
    mutable std::optional<CurrentWrite> current_write;
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
  Task<FileContext> Create(const FileContext& parent, std::string_view name,
                           stdx::stop_token);
  Task<> Write(const FileContext&, std::string_view chunk, int64_t offset,
               stdx::stop_token);
  Task<FileContext> Flush(const FileContext& item, stdx::stop_token);

  void Quit();
  void Cancel();

 private:
  std::shared_ptr<CloudProviderAccount> GetAccount(std::string_view name) const;
  Task<> Main();

  coro::Promise<void> quit_;
  event_base* event_base_;
  coro::util::EventLoop event_loop_;
  std::set<std::shared_ptr<CloudProviderAccount>> accounts_;
  bool quit_called_ = false;
  Http http_;
};

}  // namespace coro::cloudstorage

#endif  // FILESYSTEM_CONTEXT_H