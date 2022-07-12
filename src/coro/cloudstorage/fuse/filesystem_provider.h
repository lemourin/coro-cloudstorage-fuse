#ifndef CORO_CLOUDSTORAGE_FUSE_FILESYSTEM_PROVIDER_H
#define CORO_CLOUDSTORAGE_FUSE_FILESYSTEM_PROVIDER_H

#include <memory>
#include <optional>

#include "coro/cloudstorage/fuse/item_context.h"
#include "coro/cloudstorage/fuse/sparse_file.h"
#include "coro/cloudstorage/fuse/streaming_write.h"
#include "coro/util/lru_cache.h"
#include "coro/util/thread_pool.h"

namespace coro::cloudstorage::fuse {

struct FileSystemProviderConfig {
  bool buffered_write = false;
  int cache_size = 16;
};

class FileSystemProvider {
 public:
  using Item = ItemContext::Item;
  using File = ItemContext::File;
  using Directory = ItemContext::Directory;

  FileSystemProvider(util::AbstractCloudProvider* provider,
                     coro::util::ThreadPool* thread_pool,
                     FileSystemProviderConfig config)
      : provider_(provider),
        thread_pool_(thread_pool),
        content_cache_(config.cache_size,
                       SparseFileFactory{.thread_pool = thread_pool}),
        config_(config) {}

  struct PageData {
    std::vector<ItemContext> items;
    std::optional<std::string> next_page_token;
  };

  struct VolumeData {
    std::optional<int64_t> space_used;
    std::optional<int64_t> space_total;
  };

  Task<ItemContext> GetRoot(stdx::stop_token) const;
  Task<ItemContext> GetItemContext(std::string path, stdx::stop_token) const;
  Task<PageData> ReadDirectoryPage(const ItemContext& context,
                                   std::optional<std::string> page_token,
                                   stdx::stop_token) const;
  Generator<std::vector<ItemContext>> ReadDirectory(const ItemContext& context,
                                                    stdx::stop_token) const;
  Task<VolumeData> GetVolumeData(stdx::stop_token) const;
  Task<std::string> Read(const ItemContext&, int64_t offset, int64_t size,
                         stdx::stop_token) const;
  Task<ItemContext> Rename(const ItemContext& item, std::string_view new_name,
                           stdx::stop_token);
  Task<ItemContext> Move(const ItemContext& source,
                         const ItemContext& destination, stdx::stop_token);
  Task<ItemContext> CreateDirectory(const ItemContext& parent,
                                    std::string_view name, stdx::stop_token);
  Task<> Remove(const ItemContext&, stdx::stop_token);
  Task<ItemContext> Create(const ItemContext& parent, std::string_view name,
                           std::optional<int64_t> size, stdx::stop_token);
  Task<> Write(const ItemContext&, std::string_view chunk, int64_t offset,
               stdx::stop_token);
  Task<ItemContext> Flush(const ItemContext& item, stdx::stop_token);

 private:
  using QueuedRead = ItemContext::QueuedRead;
  using CurrentRead = ItemContext::CurrentRead;
  using CurrentWrite = ItemContext::CurrentWrite;
  using NewFileRead = ItemContext::NewFileRead;

  Task<ItemContext> CreateBufferedUpload(const ItemContext& parent,
                                         std::string_view name,
                                         stdx::stop_token) const;

  Task<> WriteToBufferedUpload(const ItemContext& context,
                               std::string_view chunk, int64_t offset,
                               stdx::stop_token stop_token) const;

  Task<ItemContext> FlushBufferedUpload(const ItemContext& context,
                                        stdx::stop_token stop_token) const;

  std::optional<int64_t> GetTimeToFirstByte() const;

  std::optional<int64_t> GetDownloadSpeed() const;

  void RegisterTimeToFirstByte(std::chrono::system_clock::duration time) const;

  void RegisterDownloadSpeed(std::chrono::system_clock::duration time,
                             int64_t chunk_size) const;

  struct SparseFileFactory {
    Task<std::shared_ptr<SparseFile>> operator()(std::string_view,
                                                 stdx::stop_token) const {
      co_return std::make_shared<SparseFile>(thread_pool);
    }
    coro::util::ThreadPool* thread_pool;
  };

  util::AbstractCloudProvider* provider_;
  coro::util::ThreadPool* thread_pool_;
  mutable coro::util::LRUCache<std::string, SparseFileFactory> content_cache_;
  mutable std::chrono::system_clock::duration time_to_first_byte_sum_ =
      std::chrono::seconds(0);
  mutable int64_t time_to_first_byte_sample_cnt_ = 0;
  mutable std::chrono::system_clock::duration download_speed_sum_ =
      std::chrono::seconds(0);
  mutable int64_t download_size_ = 0;
  FileSystemProviderConfig config_;
};

}  // namespace coro::cloudstorage::fuse

#endif  // CORO_CLOUDSTORAGE_FUSE_FILESYSTEM_PROVIDER_H
