#include "coro/cloudstorage/fuse/filesystem_provider.h"

#include "coro/cloudstorage/util/cloud_provider_utils.h"

namespace coro::cloudstorage::fuse {

namespace {

using ::coro::cloudstorage::util::GetItemByPath;

struct RemoveItemF {
  template <typename ItemT>
  Task<> operator()(ItemT d) && {
    co_await provider->RemoveItem(d, std::move(stop_token));
  }
  util::AbstractCloudProvider* provider;
  stdx::stop_token stop_token;
};

template <typename Item>
struct MoveItemF {
  template <typename SourceT>
  Task<Item> operator()(const SourceT& source) && {
    co_return co_await provider->MoveItem(source, destination,
                                          std::move(stop_token));
  };
  util::AbstractCloudProvider* provider;
  util::AbstractCloudProvider::Directory destination;
  stdx::stop_token stop_token;
};

template <typename ItemT>
struct RenameItemF {
  template <typename Source>
  Task<ItemT> operator()(Source item) && {
    co_return co_await provider->RenameItem(
        std::move(item), std::move(destination_name), std::move(stop_token));
  }
  util::AbstractCloudProvider* provider;
  std::string destination_name;
  stdx::stop_token stop_token;
};

}  // namespace

auto FileSystemProvider::GetRoot(stdx::stop_token stop_token) const
    -> Task<ItemContext> {
  co_return co_await GetItemContext("/", std::move(stop_token));
}

auto FileSystemProvider::GetItemContext(std::string path,
                                        stdx::stop_token stop_token) const
    -> Task<ItemContext> {
  auto item = co_await GetItemByPath(provider_, path, stop_token);
  std::optional<Directory> parent;
  if (auto it = path.find_last_of('/', path.length() - 2);
      it != std::string::npos) {
    parent = std::get<Directory>(
        co_await GetItemByPath(provider_, path.substr(0, it), stop_token));
  }
  co_return ItemContext(std::move(item), std::move(parent));
}

auto FileSystemProvider::ReadDirectoryPage(
    const ItemContext& context, std::optional<std::string> page_token,
    stdx::stop_token stop_token) const -> Task<PageData> {
  const auto& d = std::get<Directory>(context.item_.value());
  auto page_data = co_await provider_->ListDirectoryPage(
      d, std::move(page_token), std::move(stop_token));
  PageData result = {.next_page_token = std::move(page_data.next_page_token)};
  for (auto& item : page_data.items) {
    result.items.emplace_back(std::move(item), d);
  }
  co_return result;
}

auto FileSystemProvider::ReadDirectory(const ItemContext& context,
                                       stdx::stop_token stop_token) const
    -> Generator<std::vector<ItemContext>> {
  std::optional<std::string> page_token;
  do {
    auto page_data =
        co_await ReadDirectoryPage(context, std::move(page_token), stop_token);
    page_token = std::move(page_data.next_page_token);
    co_yield std::move(page_data.items);
  } while (page_token);
}

auto FileSystemProvider::GetVolumeData(stdx::stop_token stop_token) const
    -> Task<VolumeData> {
  auto data = co_await provider_->GetGeneralData(std::move(stop_token));
  co_return VolumeData{.space_used = data.space_used,
                       .space_total = data.space_total};
}

auto FileSystemProvider::Read(const ItemContext& context, int64_t offset,
                              int64_t size, stdx::stop_token stop_token) const
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
  stdx::stop_callback cb(stop_token,
                         [&] { context.stop_source_.request_stop(); });
  if (current_read.pending) {
    QueuedRead read{.offset = offset};
    current_read.reads.emplace_back(&read);
    auto guard = AtScopeExit([&] {
      current_read.reads.erase(std::find(current_read.reads.begin(),
                                         current_read.reads.end(), &read));
    });
    co_await read.semaphore;
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
    current_read.generator = provider_->GetFileContent(
        std::get<File>(context.item_.value()), http::Range{.start = offset},
        context.stop_source_.get_token());
    auto time = std::chrono::system_clock::now();
    current_read.it = co_await current_read.generator.begin();
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
      co_await ++*current_read.it;
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

auto FileSystemProvider::Rename(const ItemContext& item,
                                std::string_view new_name,
                                stdx::stop_token stop_token)
    -> Task<ItemContext> {
  auto ditem =
      co_await std::visit(RenameItemF<Item>{provider_, std::string(new_name),
                                            std::move(stop_token)},
                          item.item_.value());
  ItemContext new_item{std::move(ditem), item.parent_};
  content_cache_.Invalidate(new_item.GetId());
  co_return new_item;
}

auto FileSystemProvider::Move(const ItemContext& source,
                              const ItemContext& destination,
                              stdx::stop_token stop_token)
    -> Task<ItemContext> {
  const auto& destination_directory =
      std::get<Directory>(destination.item_.value());
  auto ditem = co_await std::visit(
      MoveItemF<Item>{provider_, destination_directory, std::move(stop_token)},
      source.item_.value());
  ItemContext new_item{std::move(ditem), destination_directory};
  content_cache_.Invalidate(new_item.GetId());
  co_return new_item;
}

auto FileSystemProvider::CreateDirectory(const ItemContext& parent,
                                         std::string_view name,
                                         stdx::stop_token stop_token)
    -> Task<ItemContext> {
  const auto& parent_directory = std::get<Directory>(parent.item_.value());
  auto new_directory = co_await provider_->CreateDirectory(
      parent_directory, std::string(name), std::move(stop_token));
  co_return ItemContext{std::move(new_directory), parent_directory};
}

auto FileSystemProvider::Remove(const ItemContext& item,
                                stdx::stop_token stop_token) -> Task<> {
  co_await std::visit(RemoveItemF{provider_, std::move(stop_token)},
                      item.item_.value());
  content_cache_.Invalidate(item.GetId());
}

auto FileSystemProvider::Create(const ItemContext& parent,
                                std::string_view name,
                                std::optional<int64_t> size,
                                stdx::stop_token stop_token)
    -> Task<ItemContext> {
  const auto& d = std::get<Directory>(parent.item_.value());
  if (config_.buffered_write ||
      (provider_->IsFileContentSizeRequired(d) && !size)) {
    co_return co_await CreateBufferedUpload(parent, name,
                                            std::move(stop_token));
  }
  ItemContext context(/*item=*/std::nullopt, d);
  context.current_streaming_write_ = std::make_unique<CurrentStreamingWrite>(
      thread_pool_, provider_, d, size, name);
  co_return context;
}

auto FileSystemProvider::CreateBufferedUpload(const ItemContext& parent,
                                              std::string_view name,
                                              stdx::stop_token) const
    -> Task<ItemContext> {
  ItemContext result{/*item=*/std::nullopt,
                     std::get<Directory>(parent.item_.value())};
  result.current_write_ = CurrentWrite{.tmpfile = util::CreateTmpFile(),
                                       .new_name = std::string(name),
                                       .mutex = std::make_unique<Mutex>()};
  co_return result;
}

auto FileSystemProvider::Write(const ItemContext& item, std::string_view chunk,
                               int64_t offset, stdx::stop_token stop_token)
    -> Task<> {
  if (!item.current_streaming_write_ &&
      (config_.buffered_write ||
       provider_->IsFileContentSizeRequired(item.parent_.value()))) {
    co_return co_await WriteToBufferedUpload(item, chunk, offset,
                                             std::move(stop_token));
  }
  if (!item.current_streaming_write_) {
    if (!item.item_ || !item.parent_) {
      throw CloudException("invalid item");
    }
    if (item.GetSize() == 0) {
      item.current_streaming_write_ = std::make_unique<CurrentStreamingWrite>(
          thread_pool_, provider_, item.parent_.value(),
          /*size=*/std::nullopt, item.GetName());
    } else {
      throw CloudException("streaming write missing");
    }
  }
  co_await item.current_streaming_write_->Write(chunk, offset,
                                                std::move(stop_token));
}

auto FileSystemProvider::Flush(const ItemContext& item,
                               stdx::stop_token stop_token)
    -> Task<ItemContext> {
  if (item.current_write_ && item.current_write_->tmpfile) {
    co_return co_await FlushBufferedUpload(item, std::move(stop_token));
  }
  if (!item.current_streaming_write_) {
    throw CloudException("streaming write missing");
  }
  auto new_item =
      co_await item.current_streaming_write_->Flush(std::move(stop_token));
  co_return ItemContext{std::move(new_item), item.parent_};
}

Task<> FileSystemProvider::WriteToBufferedUpload(
    const ItemContext& context, std::string_view chunk, int64_t offset,
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

auto FileSystemProvider::FlushBufferedUpload(const ItemContext& context,
                                             stdx::stop_token stop_token) const
    -> Task<ItemContext> {
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
  const auto& d = *context.parent_;
  auto item = co_await provider_->CreateFile(
      d, current_write.new_name,
      util::AbstractCloudProvider::FileContent{
          .data = util::ReadFile(thread_pool_, file), .size = file_size},
      stop_token);
  ItemContext new_item{std::move(item), context.parent_};
  content_cache_.Invalidate(new_item.GetId());
  co_return new_item;
}

std::optional<int64_t> FileSystemProvider::GetTimeToFirstByte() const {
  if (time_to_first_byte_sample_cnt_ == 0) {
    return std::nullopt;
  }
  return time_to_first_byte_sum_ / std::chrono::milliseconds(1) /
         time_to_first_byte_sample_cnt_;
}

std::optional<int64_t> FileSystemProvider::GetDownloadSpeed() const {
  if (download_speed_sum_ / std::chrono::milliseconds(1) == 0) {
    return std::nullopt;
  }
  return download_size_ / (download_speed_sum_ / std::chrono::milliseconds(1));
}

void FileSystemProvider::RegisterTimeToFirstByte(
    std::chrono::system_clock::duration time) const {
  time_to_first_byte_sum_ += time;
  time_to_first_byte_sample_cnt_++;
}

void FileSystemProvider::RegisterDownloadSpeed(
    std::chrono::system_clock::duration time, int64_t chunk_size) const {
  download_speed_sum_ += time;
  download_size_ += chunk_size;
}

}  // namespace coro::cloudstorage::fuse