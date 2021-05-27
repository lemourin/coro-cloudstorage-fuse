#ifndef CORO_CLOUDSTORAGE_FUSE_FILESYSTEM_PROVIDER_H
#define CORO_CLOUDSTORAGE_FUSE_FILESYSTEM_PROVIDER_H

#include <coro/util/lru_cache.h>
#include <coro/util/thread_pool.h>

#include <memory>
#include <optional>

#include "item_context.h"
#include "sparse_file.h"
#include "streaming_write.h"

namespace coro::cloudstorage::fuse {

template <typename CloudProvider>
class FileSystemProvider {
 public:
  using ItemContextT = ItemContext<CloudProvider>;
  using Item = typename ItemContextT::Item;
  using File = typename ItemContextT::File;
  using Directory = typename ItemContextT::Directory;

  FileSystemProvider(CloudProvider* provider, coro::util::EventLoop* event_loop,
                     coro::util::ThreadPool* thread_pool)
      : provider_(provider),
        event_loop_(event_loop),
        thread_pool_(thread_pool),
        content_cache_(/*cache_size=*/16,
                       SparseFileFactory{.thread_pool = thread_pool}) {}

  struct PageData {
    std::vector<ItemContextT> items;
    std::optional<std::string> next_page_token;
  };

  struct VolumeData {
    std::optional<int64_t> space_used;
    std::optional<int64_t> space_total;
  };

  Task<ItemContextT> GetRoot(stdx::stop_token) const;
  Task<ItemContextT> GetItemContext(std::string path, stdx::stop_token) const;
  Task<PageData> ReadDirectoryPage(const ItemContextT& context,
                                   std::optional<std::string> page_token,
                                   stdx::stop_token) const;
  Generator<std::vector<ItemContextT>> ReadDirectory(
      const ItemContextT& context, stdx::stop_token) const;
  Task<VolumeData> GetVolumeData(stdx::stop_token) const;
  Task<std::string> Read(const ItemContextT&, int64_t offset, int64_t size,
                         stdx::stop_token) const;
  Task<ItemContextT> Rename(const ItemContextT& item, std::string_view new_name,
                            stdx::stop_token);
  Task<ItemContextT> Move(const ItemContextT& source,
                          const ItemContextT& destination, stdx::stop_token);
  Task<ItemContextT> CreateDirectory(const ItemContextT& parent,
                                     std::string_view name, stdx::stop_token);
  Task<> Remove(const ItemContextT&, stdx::stop_token);
  Task<ItemContextT> Create(const ItemContextT& parent, std::string_view name,
                            std::optional<int64_t> size, stdx::stop_token);
  Task<> Write(const ItemContextT&, std::string_view chunk, int64_t offset,
               stdx::stop_token);
  Task<ItemContextT> Flush(const ItemContextT& item, stdx::stop_token);

 private:
  using QueuedRead = typename ItemContextT::QueuedRead;
  using CurrentRead = typename ItemContextT::CurrentRead;
  using CurrentWrite = typename ItemContextT::CurrentWrite;
  using NewFileRead = typename ItemContextT::NewFileRead;
  using CurrentStreamingWriteT = typename ItemContextT::CurrentStreamingWriteT;

  template <typename F>
  static auto Convert(const F& d) {
    if constexpr (IsDirectory<F, CloudProvider>) {
      return Directory(d);
    } else {
      static_assert(IsFile<F, CloudProvider>);
      return File(d);
    }
  }

  static auto Convert(const typename CloudProvider::Item& item) {
    return std::visit([](const auto& d) -> Item { return Convert(d); }, item);
  }

  static auto Convert(const Item& item) {
    return std::visit(
        [](const auto& d) {
          return std::visit([](const auto& d) ->
                            typename CloudProvider::Item { return d; },
                            d);
        },
        item);
  }

  Task<ItemContextT> CreateBufferedUpload(const ItemContextT& parent,
                                          std::string_view name,
                                          stdx::stop_token) const;

  Task<> WriteToBufferedUpload(const ItemContextT& context,
                               std::string_view chunk, int64_t offset,
                               stdx::stop_token stop_token) const;

  Task<ItemContextT> FlushBufferedUpload(const ItemContextT& context,
                                         stdx::stop_token stop_token) const;

  std::optional<int64_t> GetTimeToFirstByte() const {
    if (time_to_first_byte_sample_cnt_ == 0) {
      return std::nullopt;
    }
    return time_to_first_byte_sum_ / std::chrono::milliseconds(1) /
           time_to_first_byte_sample_cnt_;
  }

  std::optional<int64_t> GetDownloadSpeed() const {
    if (download_speed_sum_ / std::chrono::milliseconds(1) == 0) {
      return std::nullopt;
    }
    return download_size_ /
           (download_speed_sum_ / std::chrono::milliseconds(1));
  }

  void RegisterTimeToFirstByte(std::chrono::system_clock::duration time) const {
    time_to_first_byte_sum_ += time;
    time_to_first_byte_sample_cnt_++;
  }

  void RegisterDownloadSpeed(std::chrono::system_clock::duration time,
                             int64_t chunk_size) const {
    download_speed_sum_ += time;
    download_size_ += chunk_size;
  }

  struct SparseFileFactory {
    Task<std::shared_ptr<SparseFile>> operator()(const std::string&,
                                                 stdx::stop_token) const {
      co_return std::make_shared<SparseFile>(thread_pool);
    }
    coro::util::ThreadPool* thread_pool;
  };

  CloudProvider* provider_;
  coro::util::EventLoop* event_loop_;
  coro::util::ThreadPool* thread_pool_;
  mutable coro::util::LRUCache<std::string, SparseFileFactory> content_cache_;
  mutable std::chrono::system_clock::duration time_to_first_byte_sum_ =
      std::chrono::seconds(0);
  mutable int64_t time_to_first_byte_sample_cnt_ = 0;
  mutable std::chrono::system_clock::duration download_speed_sum_ =
      std::chrono::seconds(0);
  mutable int64_t download_size_ = 0;
};

template <typename CloudProvider>
auto FileSystemProvider<CloudProvider>::GetRoot(
    stdx::stop_token stop_token) const -> Task<ItemContextT> {
  co_return co_await GetItemContext("/", std::move(stop_token));
}

template <typename CloudProvider>
auto FileSystemProvider<CloudProvider>::GetItemContext(
    std::string path, stdx::stop_token stop_token) const -> Task<ItemContextT> {
  auto item = Convert(co_await provider_->GetItemByPath(path, stop_token));
  std::optional<Directory> parent;
  if (auto it = path.find_last_of('/', path.length() - 2);
      it != std::string::npos) {
    parent = std::get<Directory>(Convert(
        co_await provider_->GetItemByPath(path.substr(0, it), stop_token)));
  }
  co_return ItemContextT(std::move(item), std::move(parent));
}

template <typename CloudProvider>
auto FileSystemProvider<CloudProvider>::ReadDirectoryPage(
    const ItemContextT& context, std::optional<std::string> page_token,
    stdx::stop_token stop_token) const -> Task<PageData> {
  co_return co_await std::visit(
      [&](const auto& d) -> Task<PageData> {
        auto page_data = co_await provider_->ListDirectoryPage(
            d, std::move(page_token), std::move(stop_token));
        PageData result = {.next_page_token =
                               std::move(page_data.next_page_token)};
        for (auto& item : page_data.items) {
          result.items.emplace_back(Convert(std::move(item)), d);
        }
        co_return result;
      },
      std::get<Directory>(context.item_.value()));
}

template <typename CloudProvider>
auto FileSystemProvider<CloudProvider>::ReadDirectory(
    const ItemContextT& context, stdx::stop_token stop_token) const
    -> Generator<std::vector<ItemContextT>> {
  std::optional<std::string> page_token;
  do {
    auto page_data =
        co_await ReadDirectoryPage(context, std::move(page_token), stop_token);
    page_token = std::move(page_data.next_page_token);
    co_yield std::move(page_data.items);
  } while (page_token);
}

template <typename CloudProvider>
auto FileSystemProvider<CloudProvider>::GetVolumeData(
    stdx::stop_token stop_token) const -> Task<VolumeData> {
  auto data = co_await provider_->GetGeneralData(std::move(stop_token));
  if constexpr (HasUsageData<decltype(data)>) {
    co_return VolumeData{.space_used = data.space_used,
                         .space_total = data.space_total};
  } else {
    co_return VolumeData{.space_used = 0, .space_total = 0};
  }
}

template <typename CloudProvider>
auto FileSystemProvider<CloudProvider>::Read(const ItemContextT& context,
                                             int64_t offset, int64_t size,
                                             stdx::stop_token stop_token) const
    -> Task<std::string> {
  using ::coro::util::AtScopeExit;

  auto item_size = context.GetSize();
  if (!item_size) {
    throw CloudException("size unknown");
  }
  if (*item_size == 0) {
    co_return "";
  }
  if (offset >= *item_size) {
    throw CloudException("invalid offset " + std::to_string(offset) +
                         " >= " + std::to_string(*item_size));
  }
  size = std::min<int64_t>(size, *item_size - offset);

  auto cache_file = co_await content_cache_.Get(context.GetId(), stop_token);
  if (!context.current_read_) {
    context.current_read_ = CurrentRead{.current_offset = INT64_MAX};
  }
  CurrentRead& current_read = *context.current_read_;
  if (std::optional<std::string> chunk =
          co_await cache_file->Read(offset, static_cast<size_t>(size))) {
    co_return *chunk;
  }
  if (current_read.pending) {
    QueuedRead read{.offset = offset};
    current_read.reads.emplace_back(&read);
    auto guard = AtScopeExit([&] {
      current_read.reads.erase(std::find(current_read.reads.begin(),
                                         current_read.reads.end(), &read));
    });
    co_await InterruptibleAwait(read.semaphore, stop_token);
  }
  current_read.pending = true;
  auto guard = AtScopeExit([&] {
    current_read.pending = false;
    auto it = std::min_element(
        current_read.reads.begin(), current_read.reads.end(),
        [&](auto* d1, auto* d2) { return d1->offset < d2->offset; });
    if (it != current_read.reads.end()) {
      (*it)->semaphore.SetValue();
    }
  });
  auto start_read = [&](int64_t offset) -> Task<> {
    std::cerr << "START READ " << offset << " " << context.GetName() << "\n";
    current_read.generator = std::visit(
        [&](const auto& d) {
          return provider_->GetFileContent(d, http::Range{.start = offset},
                                           context.stop_source_.get_token());
        },
        std::get<File>(context.item_.value()));
    auto time = std::chrono::system_clock::now();
    current_read.it =
        co_await InterruptibleAwait(current_read.generator.begin(), stop_token);
    RegisterTimeToFirstByte(std::chrono::system_clock::now() - time);
    current_read.current_offset = offset;
    current_read.chunk.clear();
  };
  int64_t requested_offset = offset;
  if (offset > current_read.current_offset) {
    auto time_to_first_byte = GetTimeToFirstByte();
    auto download_speed = GetDownloadSpeed();
    if (time_to_first_byte && download_speed) {
      std::cerr << "TTFB = " << *time_to_first_byte << " DOWNLOAD SPEED "
                << *download_speed << "\n";
    }
    if (time_to_first_byte && download_speed &&
        (offset - current_read.current_offset) / *download_speed <=
            *time_to_first_byte) {
      offset = current_read.current_offset;
    }
  }
  if (offset != current_read.current_offset) {
    co_await start_read(offset);
  }
  auto time = std::chrono::system_clock::now();
  std::string chunk;
  auto append = [&](std::string current_chunk) -> Task<> {
    co_await cache_file->Write(current_read.current_offset, current_chunk);
    int64_t chunk_size = static_cast<int64_t>(current_chunk.size());
    if (current_read.current_offset + chunk_size - 1 >= requested_offset &&
        current_read.current_offset < requested_offset) {
      chunk += std::move(current_chunk)
                   .substr(static_cast<size_t>(requested_offset -
                                               current_read.current_offset));
    } else if (current_read.current_offset >= requested_offset) {
      chunk += current_chunk;
    }
    current_read.current_offset += chunk_size;
  };
  co_await append(std::move(std::exchange(current_read.chunk, "")));
  while (static_cast<int64_t>(chunk.size()) < size &&
         *current_read.it != std::end(current_read.generator)) {
    co_await append(std::move(**current_read.it));
    std::optional<std::exception_ptr> exception;
    try {
      auto task = ++*current_read.it;
      co_await InterruptibleAwait(std::move(task), stop_token);
    } catch (const InterruptedException&) {
      throw;
    } catch (...) {
      exception = std::current_exception();
    }
    if (exception) {
      current_read.current_offset = INT64_MAX;
      co_await start_read(requested_offset + chunk.size());
    }
  }
  RegisterDownloadSpeed(std::chrono::system_clock::now() - time, size);
  current_read.current_offset = requested_offset + size;
  if (static_cast<int64_t>(chunk.size()) > size) {
    current_read.chunk =
        std::string(chunk.begin() + static_cast<size_t>(size), chunk.end());
    chunk.resize(static_cast<size_t>(size));
  }
  co_return chunk;
}

template <typename CloudProvider>
auto FileSystemProvider<CloudProvider>::Rename(const ItemContextT& item,
                                               std::string_view new_name,
                                               stdx::stop_token stop_token)
    -> Task<ItemContextT> {
  auto ditem = co_await std::visit(
      [&](const auto& d) -> Task<Item> {
        co_return co_await std::visit(
            [&](const auto& d) -> Task<Item> {
              co_return co_await provider_->RenameItem(d, std::string(new_name),
                                                       std::move(stop_token));
            },
            d);
      },
      item.item_.value());
  ItemContextT new_item{std::move(ditem), item.parent_};
  content_cache_.Invalidate(new_item.GetId());
  co_return new_item;
}

template <typename CloudProvider>
auto FileSystemProvider<CloudProvider>::Move(const ItemContextT& source,
                                             const ItemContextT& destination,
                                             stdx::stop_token stop_token)
    -> Task<ItemContextT> {
  const auto& destination_directory =
      std::get<Directory>(destination.item_.value());
  auto ditem = co_await std::visit(
      [&](const auto& source, const auto& destination) -> Task<Item> {
        co_return co_await std::visit(
            [&](const auto& source) -> Task<Item> {
              co_return co_await provider_->MoveItem(source, destination,
                                                     std::move(stop_token));
            },
            source);
      },
      source.item_.value(), destination_directory);
  ItemContextT new_item{std::move(ditem), destination_directory};
  content_cache_.Invalidate(new_item.GetId());
  co_return new_item;
}

template <typename CloudProvider>
auto FileSystemProvider<CloudProvider>::CreateDirectory(
    const ItemContextT& parent, std::string_view name,
    stdx::stop_token stop_token) -> Task<ItemContextT> {
  const auto& parent_directory = std::get<Directory>(parent.item_.value());
  auto new_directory = co_await std::visit(
      [&](const auto& d) -> Task<Item> {
        co_return co_await provider_->CreateDirectory(d, std::string(name),
                                                      std::move(stop_token));
      },
      parent_directory);
  co_return ItemContextT{std::move(new_directory), parent_directory};
}

template <typename CloudProvider>
auto FileSystemProvider<CloudProvider>::Remove(const ItemContextT& item,
                                               stdx::stop_token stop_token)
    -> Task<> {
  co_await std::visit(
      [&](const auto& d) -> Task<> {
        co_await provider_->RemoveItem(d, std::move(stop_token));
      },
      Convert(item.item_.value()));
  content_cache_.Invalidate(item.GetId());
}

template <typename CloudProvider>
auto FileSystemProvider<CloudProvider>::Create(const ItemContextT& parent,
                                               std::string_view name,
                                               std::optional<int64_t> size,
                                               stdx::stop_token stop_token)
    -> Task<ItemContextT> {
  if (CloudProvider::kIsFileContentSizeRequired && !size) {
    co_return co_await CreateBufferedUpload(parent, name,
                                            std::move(stop_token));
  }
  co_return std::visit(
      [&]<typename Directory>(const Directory& parent) {
        ItemContextT d(/*item=*/std::nullopt, parent);
        d.current_streaming_write_ = std::make_unique<CurrentStreamingWriteT>(
            std::in_place_type_t<
                CurrentStreamingWrite<CloudProvider, Directory>>{},
            thread_pool_, event_loop_, provider_, parent, size, name);
        return d;
      },
      std::get<Directory>(parent.item_.value()));
}

template <typename CloudProvider>
auto FileSystemProvider<CloudProvider>::CreateBufferedUpload(
    const ItemContextT& parent, std::string_view name, stdx::stop_token) const
    -> Task<ItemContextT> {
  ItemContextT result{/*item=*/std::nullopt,
                      std::get<Directory>(parent.item_.value())};
  result.current_write_ = CurrentWrite{.tmpfile = util::CreateTmpFile(),
                                       .new_name = std::string(name),
                                       .mutex = std::make_unique<Mutex>()};
  co_return result;
}

template <typename CloudProvider>
auto FileSystemProvider<CloudProvider>::Write(const ItemContextT& item,
                                              std::string_view chunk,
                                              int64_t offset,
                                              stdx::stop_token stop_token)
    -> Task<> {
  if (item.current_write_ && item.current_write_->tmpfile) {
    co_return co_await WriteToBufferedUpload(item, chunk, offset,
                                             std::move(stop_token));
  }
  if (!item.current_streaming_write_) {
    if (!item.item_ || !item.parent_) {
      throw CloudException("invalid item");
    }
    if (item.GetSize() == 0) {
      std::visit(
          [&]<typename Directory>(const Directory& parent) {
            item.current_streaming_write_ =
                std::make_unique<CurrentStreamingWriteT>(
                    std::in_place_type_t<
                        CurrentStreamingWrite<CloudProvider, Directory>>{},
                    thread_pool_, event_loop_, provider_, parent,
                    /*size=*/std::nullopt, item.GetName());
          },
          item.parent_.value());
    } else {
      throw CloudException("streaming write missing");
    }
  }
  co_await std::visit(
      [&](auto& write) -> Task<> {
        co_await write.Write(chunk, offset, std::move(stop_token));
      },
      *item.current_streaming_write_);
}

template <typename CloudProvider>
auto FileSystemProvider<CloudProvider>::Flush(const ItemContextT& item,
                                              stdx::stop_token stop_token)
    -> Task<ItemContextT> {
  if (item.current_write_ && item.current_write_->tmpfile) {
    co_return co_await FlushBufferedUpload(item, std::move(stop_token));
  }
  if (!item.current_streaming_write_) {
    throw CloudException("streaming write missing");
  }
  co_return co_await std::visit(
      [&](auto& write) -> Task<ItemContextT> {
        auto new_item = co_await write.Flush(std::move(stop_token));
        co_return ItemContextT{std::move(new_item), item.parent_};
      },
      *item.current_streaming_write_);
}

template <typename CloudProvider>
Task<> FileSystemProvider<CloudProvider>::WriteToBufferedUpload(
    const ItemContextT& context, std::string_view chunk, int64_t offset,
    stdx::stop_token stop_token) const {
  if (!context.current_write_) {
    if (!context.item_) {
      throw CloudException("invalid item");
    }
    auto file = util::CreateTmpFile();
    NewFileRead read{.provider = provider_,
                     .thread_pool = thread_pool_,
                     .item = std::get<File>(*context.item_),
                     .file = file.get()};
    context.current_write_ =
        CurrentWrite{.tmpfile = std::move(file),
                     .new_name = context.GetName(),
                     .new_file_read = SharedPromise(std::move(read)),
                     .mutex = std::make_unique<Mutex>()};
  }
  const auto& current_write = *context.current_write_;
  if (current_write.new_file_read) {
    co_await current_write.new_file_read->Get(stop_token);
  }
  auto lock = co_await UniqueLock::Create(current_write.mutex.get());
  co_await util::WriteFile(thread_pool_, current_write.tmpfile.get(), offset,
                           chunk);
}

template <typename CloudProvider>
auto FileSystemProvider<CloudProvider>::FlushBufferedUpload(
    const ItemContextT& context, stdx::stop_token stop_token) const
    -> Task<ItemContextT> {
  if (!context.current_write_) {
    throw CloudException("invalid flush");
  }
  if (!context.parent_) {
    throw CloudException("invalid parent");
  }

  const auto& current_write = *context.current_write_;
  if (current_write.new_file_read) {
    co_await current_write.new_file_read->Get(stop_token);
  }

  auto lock = co_await UniqueLock::Create(current_write.mutex.get());
  auto* file = current_write.tmpfile.get();
  auto file_size = co_await util::GetFileSize(thread_pool_, file);
  auto item = co_await std::visit(
      [&](const auto& d) -> Task<File> {
        co_return co_await provider_->CreateFile(
            d, current_write.new_name,
            typename CloudProvider::FileContent{
                .data = util::ReadFile(thread_pool_, file), .size = file_size},
            stop_token);
      },
      *context.parent_);
  ItemContextT new_item{std::move(item), context.parent_};
  content_cache_.Invalidate(new_item.GetId());
  co_return new_item;
}

}  // namespace coro::cloudstorage::fuse

#endif  // CORO_CLOUDSTORAGE_FUSE_FILESYSTEM_PROVIDER_H
