#ifndef FILESYSTEM_CONTEXT_H
#define FILESYSTEM_CONTEXT_H

#include <coro/cloudstorage/abstract_cloud_provider.h>
#include <coro/cloudstorage/cloud_exception.h>
#include <coro/cloudstorage/cloud_factory.h>
#include <coro/cloudstorage/cloud_provider.h>
#include <coro/cloudstorage/providers/box.h>
#include <coro/cloudstorage/providers/dropbox.h>
#include <coro/cloudstorage/providers/google_drive.h>
#include <coro/cloudstorage/providers/mega.h>
#include <coro/cloudstorage/providers/one_drive.h>
#include <coro/cloudstorage/providers/pcloud.h>
#include <coro/cloudstorage/providers/yandex_disk.h>
#include <coro/cloudstorage/util/account_manager_handler.h>
#include <coro/http/cache_http.h>
#include <coro/http/curl_http.h>
#include <coro/http/http_server.h>
#include <coro/promise.h>
#include <coro/stdx/concepts.h>
#include <coro/task.h>
#include <coro/util/event_loop.h>
#include <coro/util/lru_cache.h>
#include <coro/util/thread_pool.h>
#include <coro/util/type_list.h>
#include <event.h>

#include <future>

namespace coro::cloudstorage {

class FileSystemContext {
 public:
  using Http = http::CacheHttp<http::CurlHttp>;
  using EventLoop = ::coro::util::EventLoop;
  using ThreadPool = ::coro::util::ThreadPool;

  struct Config {
    bool buffered_write;
    int cache_size;
  };

  struct AccountListener;

  using CloudProviders = coro::util::TypeList<GoogleDrive, Mega, OneDrive,
                                              Dropbox, Box, YandexDisk, PCloud>;

  using AccountManagerHandlerT =
      util::AccountManagerHandler<CloudProviders, CloudFactory<EventLoop, Http>,
                                  AccountListener>;
  using CloudProviderAccount = AccountManagerHandlerT::CloudProviderAccount;
  using HttpServer = http::HttpServer<AccountManagerHandlerT>;

  struct AccountListener {
    void OnCreate(CloudProviderAccount*);
    void OnDestroy(CloudProviderAccount*);
    FileSystemContext* context;
  };

  struct VolumeData {
    int64_t space_used;
    std::optional<int64_t> space_total;
  };

  using AbstractCloudProvider = AccountManagerHandlerT::AbstractCloudProviderT;
  using AbstractCloudProviderT = AbstractCloudProvider::CloudProvider;

  using GenericItem = AbstractCloudProvider::GenericItem;

  struct Item {
    Item(std::weak_ptr<CloudProviderAccount> account,
         AbstractCloudProviderT::Item item)
        : account(std::move(account)), item(std::move(item)) {}

    AbstractCloudProviderT provider() const;
    stdx::stop_token stop_token() const;
    GenericItem GetGenericItem() const;
    std::shared_ptr<CloudProviderAccount> GetAccount() const;

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

  struct Range {
    int64_t offset;
    size_t size;

    bool operator<(const Range& other) const {
      return std::tie(offset, size) < std::tie(other.offset, other.size);
    }
  };

  class SparseFile {
   public:
    SparseFile();

    Task<> Write(ThreadPool*, int64_t offset, std::string_view chunk);
    Task<std::optional<std::string>> Read(ThreadPool* thread_pool,
                                          int64_t offset, size_t size) const;

   private:
    std::set<Range> ranges_;
    std::unique_ptr<FILE, FileDeleter> file_;
  };

  struct QueuedRead {
    int64_t offset;
    Promise<void> semaphore;
  };

  struct CurrentRead {
    Generator<std::string> generator;
    std::optional<Generator<std::string>::iterator> it;
    std::string chunk;
    int64_t current_offset;
    bool pending;
    std::vector<QueuedRead*> reads;
    std::unique_ptr<StopTokenData> stop_token_data;
  };

  struct NewFileRead {
    Task<> operator()();
    ThreadPool* thread_pool;
    Item item;
    std::FILE* file;
    stdx::stop_token stop_token;
  };

  struct CurrentWrite {
    std::unique_ptr<std::FILE, FileDeleter> tmpfile;
    std::string new_name;
    std::optional<SharedPromise<NewFileRead>> new_file_read;
    std::unique_ptr<StopTokenData> stop_token_data;
  };

  class CurrentStreamingWrite {
   public:
    CurrentStreamingWrite(Item parent, std::optional<int64_t> size,
                          std::string_view name);
    ~CurrentStreamingWrite();

    Task<> Write(ThreadPool*, std::string_view chunk, int64_t offset,
                 stdx::stop_token);
    Task<Item> Flush(stdx::stop_token);

   private:
    Generator<std::string> GetStream();
    Task<AbstractCloudProviderT::Item> CreateFile();

    Item parent_;
    std::optional<int64_t> size_;
    std::string name_;
    StopTokenData stop_token_data_;
    bool flushed_ = false;
    Promise<std::string> current_chunk_;
    Promise<void> done_;
    int64_t current_offset_ = 0;
    std::unique_ptr<FILE, FileDeleter> buffer_;
    std::vector<Range> ranges_;
    Promise<AbstractCloudProviderT::Item> item_promise_;
  };

  struct FileContext {
    std::optional<Item> item;
    std::optional<Item> parent;

    mutable std::optional<CurrentRead> current_read;
    mutable std::optional<CurrentWrite> current_write;
    mutable std::unique_ptr<CurrentStreamingWrite> current_streaming_write;
  };

  struct PageData {
    std::vector<FileContext> items;
    std::optional<std::string> next_page_token;
  };

  explicit FileSystemContext(event_base*, Config = {.buffered_write = false,
                                                    .cache_size = 16});
  ~FileSystemContext();

  FileSystemContext(const FileSystemContext&) = delete;
  FileSystemContext(FileSystemContext&&) = delete;
  FileSystemContext& operator=(const FileSystemContext&) = delete;
  FileSystemContext& operator=(FileSystemContext&&) = delete;

  template <typename F>
  auto RunOnEventLoop(F func) {
    return event_loop_.RunOnEventLoop(std::move(func));
  }

  template <typename F>
  auto Do(F func) {
    using ResultType = decltype(func().await_resume());
    std::promise<ResultType> result;
    RunOnEventLoop([&result, &func]() -> Task<> {
      try {
        result.set_value(co_await func());
      } catch (...) {
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
                           std::optional<int64_t> size, stdx::stop_token);
  Task<> Write(const FileContext&, std::string_view chunk, int64_t offset,
               stdx::stop_token);
  Task<FileContext> Flush(const FileContext& item, stdx::stop_token);

  void Quit();
  void Cancel();

  auto Wait(int ms) const { return event_loop_.Wait(ms); }

 private:
  Task<FileContext> CreateBufferedUpload(const FileContext& parent,
                                         std::string_view name,
                                         stdx::stop_token);
  Task<> WriteToBufferedUpload(const FileContext&, std::string_view chunk,
                               int64_t offset, stdx::stop_token);
  Task<FileContext> FlushBufferedUpload(const FileContext& item,
                                        stdx::stop_token);

  std::shared_ptr<CloudProviderAccount> GetAccount(std::string_view name) const;

  struct CacheKey {
    intptr_t account_id;
    std::string item_id;

    bool operator==(const CacheKey& other) const {
      return std::tie(account_id, item_id) ==
             std::tie(other.account_id, other.item_id);
    }
  };

  static CacheKey GetCacheKey(const FileContext& context) {
    return CacheKey{.account_id = context.item->provider().id(),
                    .item_id = context.item->GetGenericItem().id};
  }

  struct HashCacheKey {
    auto operator()(const CacheKey& d) const {
      return std::hash<std::string>{}(std::to_string(d.account_id) + d.item_id);
    }
  };

  struct SparseFileFactory {
    Task<std::shared_ptr<SparseFile>> operator()(const CacheKey&,
                                                 stdx::stop_token) const {
      co_return std::make_shared<SparseFile>();
    }
  };

  event_base* event_base_;
  coro::util::EventLoop event_loop_;
  std::set<std::shared_ptr<CloudProviderAccount>> accounts_;
  bool quit_called_ = false;
  Http http_;
  Config config_;
  mutable coro::util::LRUCache<CacheKey, SparseFileFactory, HashCacheKey>
      content_cache_;
  CloudFactory<EventLoop, Http> cloud_factory_;
  std::optional<HttpServer> http_server_;
  mutable ThreadPool thread_pool_;
};

}  // namespace coro::cloudstorage

#endif  // FILESYSTEM_CONTEXT_H