#ifndef CORO_CLOUDSTORAGE_FUSE_ITEM_CONTEXT_H
#define CORO_CLOUDSTORAGE_FUSE_ITEM_CONTEXT_H

#include "coro/cloudstorage/fuse/sparse_file.h"
#include "coro/cloudstorage/fuse/streaming_write.h"
#include "coro/cloudstorage/util/abstract_cloud_provider.h"
#include "coro/shared_promise.h"

namespace coro::cloudstorage::fuse {

class ItemContext {
 public:
  using File = util::AbstractCloudProvider::File;
  using Directory = util::AbstractCloudProvider::Directory;
  using Item = util::AbstractCloudProvider::Item;

  enum class ItemType { kDirectory, kFile };

  ItemContext() : ItemContext(std::nullopt, std::nullopt) {}
  ItemContext(std::optional<Item> item, std::optional<Directory> parent)
      : item_(std::move(item)), parent_(std::move(parent)) {}

  ~ItemContext() { stop_source_.request_stop(); }

  ItemContext(const ItemContext&) = delete;
  ItemContext(ItemContext&&) = default;
  ItemContext& operator=(const ItemContext&) = delete;
  ItemContext& operator=(ItemContext&&) = default;

  static ItemContext From(const ItemContext& item) {
    return ItemContext(item.item_, item.parent_);
  }

  std::string GetId() const;
  std::optional<int64_t> GetTimestamp() const;
  std::optional<int64_t> GetSize() const;
  ItemType GetType() const;
  std::string GetName() const;
  std::optional<std::string> GetMimeType() const;
  bool IsPending() const { return !item_; }

 private:
  friend class FileSystemProvider;

  struct NewFileRead {
    Task<> operator()();

    util::AbstractCloudProvider* provider;
    coro::util::ThreadPool* thread_pool;
    File item;
    std::FILE* file;
    stdx::stop_token stop_token;
  };

  struct CurrentWrite {
    std::unique_ptr<std::FILE, util::FileDeleter> tmpfile;
    std::string new_name;
    std::optional<SharedPromise<NewFileRead>> new_file_read;
    std::unique_ptr<Mutex> mutex;
  };

  mutable std::optional<CurrentWrite> current_write_;
  mutable std::unique_ptr<CurrentStreamingWrite> current_streaming_write_;

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
  };

  std::optional<Item> item_;
  std::optional<Directory> parent_;
  mutable std::optional<CurrentRead> current_read_;
  mutable stdx::stop_source stop_source_;
};

}  // namespace coro::cloudstorage::fuse

#endif  // CORO_CLOUDSTORAGE_FUSE_ITEM_CONTEXT_H
