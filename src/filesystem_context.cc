#include "filesystem_context.h"

#include <coro/cloudstorage/abstract_cloud_provider.h>
#include <coro/cloudstorage/cloud_exception.h>
#include <coro/http/http_server.h>
#include <coro/util/stop_token_or.h>

namespace coro::cloudstorage {

namespace {

using ::coro::util::AtScopeExit;
using ::coro::util::StopTokenOr;
using ::coro::util::TypeList;

template <typename T>
concept HasUsageData = requires(T v) {
  { v.space_used }
  ->stdx::convertible_to<int64_t>;
  { v.space_total }
  ->stdx::convertible_to<int64_t>;
};

template <typename T, typename C>
std::vector<T> SplitString(const T& string, C delim) {
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

StopTokenOr GetToken(const FileSystemContext::FileContext& context,
                     stdx::stop_token stop_token) {
  if (!context.item) {
    throw std::invalid_argument("item not associated with any account");
  }
  return StopTokenOr(std::move(stop_token), context.item->stop_token());
}

auto CreateTmpFile() {
  return std::unique_ptr<std::FILE, FileSystemContext::FileDeleter>([] {
#ifdef _MSC_VER
    std::FILE* file;
    if (tmpfile_s(&file) != 0) {
      throw std::runtime_error("couldn't create tmpfile");
    }
    return file;
#else
    return std::tmpfile();
#endif
  }());
}

int64_t GetFileSize(std::FILE* file) {
  fseek(file, 0, SEEK_END);
  int64_t size = ftell(file);
  fseek(file, 0, SEEK_SET);
  return size;
}

Generator<std::string> ReadFile(std::FILE* file) {
  const int kBufferSize = 4096;
  char buffer[kBufferSize];
  while (feof(file) == 0) {
    size_t size = fread(buffer, 1, kBufferSize, file);
    if (int error = ferror(file)) {
      throw std::runtime_error("read error");
    }
    co_yield std::string(buffer, size);
  }
}

}  // namespace

auto FileSystemContext::Item::provider() const -> AbstractCloudProviderT {
  auto acc = account.lock();
  if (!acc) {
    throw CloudException(CloudException::Type::kNotFound);
  }
  return std::visit(
      [](auto& provider) { return AbstractCloudProviderT(&provider); },
      acc->provider);
}

stdx::stop_token FileSystemContext::Item::stop_token() const {
  auto acc = account.lock();
  if (!acc) {
    throw CloudException(CloudException::Type::kNotFound);
  }
  return acc->stop_source.get_token();
}

auto FileSystemContext::Item::GetGenericItem() const -> GenericItem {
  return AbstractCloudProviderT::ToGenericItem(item);
}

void FileSystemContext::AccountListener::OnCreate(CloudProviderAccount* d) {
  context->accounts_.insert(
      std::shared_ptr<CloudProviderAccount>(d, [](auto) {}));
  std::cerr << "CREATED " << d->id << "\n";
}

void FileSystemContext::AccountListener::OnDestroy(CloudProviderAccount* d) {
  context->accounts_.erase(
      std::shared_ptr<CloudProviderAccount>(d, [](auto) {}));
  std::cerr << "REMOVED " << d->id << "\n";
}

FileSystemContext::FileSystemContext(event_base* event_base, Config config)
    : event_base_(event_base),
      event_loop_(event_base_),
      http_(http::CurlHttp(event_base)),
      config_(std::move(config)) {
  Invoke(Main());
}

FileSystemContext::~FileSystemContext() { Quit(); }

void FileSystemContext::Cancel() {
  for (const auto& account : accounts_) {
    account->stop_source.request_stop();
  }
}

void FileSystemContext::Quit() {
  if (!quit_called_) {
    quit_called_ = true;
    Cancel();
    quit_.SetValue();
  }
}

auto FileSystemContext::GetGenericItem(const FileContext& ctx) -> GenericItem {
  if (!ctx.item) {
    return GenericItem{.name = "root", .type = GenericItem::Type::kDirectory};
  }
  return ctx.item->GetGenericItem();
}

auto FileSystemContext::GetFileContext(std::string path,
                                       stdx::stop_token stop_token) const
    -> Task<FileContext> {
  auto components = SplitString(path, '/');
  if (components.empty()) {
    co_return FileContext{};
  }
  auto account = GetAccount(*components.begin());
  std::string provider_path;
  for (size_t i = 1; i < components.size(); i++) {
    provider_path += "/" + components[i];
  }
  StopTokenOr stop_token_or(account->stop_source.get_token(),
                            std::move(stop_token));
  co_return co_await std::visit(
      [&](auto& d) -> Task<FileContext> {
        auto it = provider_path.find_last_of('/', provider_path.length() - 2);
        auto item = Item(account, co_await d.GetItemByPath(
                                      provider_path, stop_token_or.GetToken()));
        std::optional<Item> parent;
        if (it != std::string::npos) {
          parent = Item(account,
                        co_await d.GetItemByPath(provider_path.substr(0, it),
                                                 stop_token_or.GetToken()));
        }
        co_return FileContext{.item = std::move(item),
                              .parent = std::move(parent)};
      },
      account->provider);
}

auto FileSystemContext::ReadDirectory(const FileContext& context,
                                      stdx::stop_token stop_token) const
    -> Generator<std::vector<FileContext>> {
  std::optional<std::string> page_token;
  do {
    auto page_data =
        co_await ReadDirectoryPage(context, std::move(page_token), stop_token);
    page_token = std::move(page_data.next_page_token);
    co_yield std::move(page_data.items);
  } while (page_token);
}

auto FileSystemContext::ReadDirectoryPage(const FileContext& context,
                                          std::optional<std::string> page_token,
                                          stdx::stop_token stop_token) const
    -> Task<PageData> {
  if (!context.item) {
    std::vector<FileContext> result;
    for (auto account : accounts_) {
      auto root = co_await std::visit(
          [&](auto& provider) -> Task<FileContext> {
            StopTokenOr stop_token_or(stop_token,
                                      account->stop_source.get_token());
            auto directory =
                co_await provider.GetRoot(stop_token_or.GetToken());
            directory.name = account->id;
            co_return FileContext{.item = Item(account, std::move(directory))};
          },
          account->provider);
      result.emplace_back(std::move(root));
    }
    co_return PageData{.items = std::move(result)};
  }
  auto stop_token_or = GetToken(context, std::move(stop_token));
  auto page_data = co_await context.item->provider().ListDirectoryPage(
      context.item->item, std::move(page_token), stop_token_or.GetToken());
  PageData result = {.next_page_token = std::move(page_data.next_page_token)};
  for (auto& item : page_data.items) {
    result.items.emplace_back(
        FileContext{.item = Item(context.item->account, std::move(item)),
                    .parent = context.item});
  }
  co_return std::move(result);
}

auto FileSystemContext::GetVolumeData(stdx::stop_token stop_token) const
    -> Task<VolumeData> {
  std::vector<Task<VolumeData>> tasks;
  for (const auto& account : accounts_) {
    tasks.emplace_back(std::visit(
        [&](auto& provider) -> Task<VolumeData> {
          StopTokenOr stop_token_or(account->stop_source.get_token(),
                                    std::move(stop_token));
          auto data =
              co_await provider.GetGeneralData(stop_token_or.GetToken());
          if constexpr (HasUsageData<decltype(data)>) {
            co_return VolumeData{.space_used = data.space_used,
                                 .space_total = data.space_total};
          } else {
            co_return VolumeData{.space_used = 0, .space_total = 0};
          }
        },
        account->provider));
  }
  VolumeData total = {.space_used = 0, .space_total = 0};
  for (auto& d : tasks) {
    auto data = co_await std::move(d);
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

Task<std::string> FileSystemContext::Read(const FileContext& context,
                                          int64_t offset, int64_t size,
                                          stdx::stop_token stop_token) const {
  if (!context.item) {
    throw CloudException("not a file");
  }
  auto stop_token_or = GetToken(context, stop_token);
  auto generic_item = GetGenericItem(context);
  if (!generic_item.size) {
    throw CloudException("size unknown");
  }
  size = std::min<int64_t>(size, *generic_item.size - offset);
  auto& current_read = context.current_read;
  if (current_read &&
      (current_read->pending || offset > current_read->current_offset)) {
    if (!current_read->pending) {
      if (offset - current_read->current_offset <= 4 * size) {
        const int max_wait = 128;
        int current_delay = 0;
        while (!current_read->pending && current_delay < max_wait) {
          co_await event_loop_.Wait(current_delay, stop_token_or.GetToken());
          current_delay = current_delay * 2 + 1;
        }
      }
    }
    if (current_read->pending) {
      QueuedRead queued_read{.offset = offset, .size = size};
      auto awaiter_guard = AtScopeExit([&] {
        context.queued_reads.erase(std::find(context.queued_reads.begin(),
                                             context.queued_reads.end(),
                                             &queued_read));
      });
      context.queued_reads.emplace_back(&queued_read);
      co_await InterruptibleAwait(queued_read.awaiter,
                                  stop_token_or.GetToken());
    }
  }
  try {
    if (!current_read || current_read->current_offset != offset) {
      std::cerr << "STARTING READ " << generic_item.name << " " << offset
                << "\n";
      current_read = CurrentRead{
          .current_offset = offset,
          .pending = true,
          .stop_token_data =
              std::make_unique<StopTokenData>(context.item->stop_token())};
      current_read->generator = context.item->provider().GetFileContent(
          context.item->item, http::Range{.start = offset},
          current_read->stop_token_data->stop_token_or.GetToken());
      current_read->it = co_await InterruptibleAwait(
          current_read->generator.begin(), stop_token_or.GetToken());
    } else {
      current_read->pending = true;
    }
    std::string chunk = std::exchange(current_read->chunk, "");
    while (static_cast<int64_t>(chunk.size()) < size &&
           *current_read->it != std::end(current_read->generator)) {
      chunk += std::move(**current_read->it);
      co_await InterruptibleAwait(++*current_read->it,
                                  stop_token_or.GetToken());
    }
    current_read->current_offset = offset + size;
    if (static_cast<int64_t>(chunk.size()) > size) {
      current_read->chunk =
          std::string(chunk.begin() + static_cast<size_t>(size), chunk.end());
      chunk.resize(static_cast<size_t>(size));
    }
    current_read->pending = false;

    bool woken_up_someone = false;
    for (QueuedRead* read : context.queued_reads) {
      if (context.current_read->current_offset == read->offset) {
        read->awaiter.SetValue();
        woken_up_someone = true;
        break;
      }
    }
    if (!woken_up_someone && !context.queued_reads.empty()) {
      (*context.queued_reads.begin())->awaiter.SetValue();
    }

    co_return std::move(chunk);
  } catch (const std::exception& e) {
    auto current_offset =
        current_read ? current_read->current_offset : offset + size;
    current_read = std::nullopt;

    bool woken_up_someone = false;
    for (QueuedRead* read : context.queued_reads) {
      if (current_offset == read->offset) {
        read->awaiter.SetException(e);
        woken_up_someone = true;
        break;
      }
    }
    if (!woken_up_someone && !context.queued_reads.empty()) {
      (*context.queued_reads.begin())->awaiter.SetValue();
    }

    throw;
  }
}

auto FileSystemContext::Rename(const FileContext& context,
                               std::string_view new_name,
                               stdx::stop_token stop_token)
    -> Task<FileContext> {
  if (!context.item) {
    throw CloudException("cannot rename root");
  }

  auto stop_token_or = GetToken(context, std::move(stop_token));
  auto item = co_await context.item->provider().RenameItem(
      context.item->item, new_name, stop_token_or.GetToken());
  http_.InvalidateCache();
  co_return FileContext{.item = Item(context.item->account, std::move(item)),
                        .parent = context.item};
}

auto FileSystemContext::Move(const FileContext& source,
                             const FileContext& destination,
                             stdx::stop_token stop_token) -> Task<FileContext> {
  if (!source.item || !destination.item) {
    throw CloudException("cannot move from / to root");
  }
  if (source.item->account.lock() != destination.item->account.lock()) {
    throw CloudException("cannot move between different accounts");
  }
  auto stop_token_or = GetToken(source, std::move(stop_token));
  auto item = co_await source.item->provider().MoveItem(
      source.item->item, destination.item->item, stop_token_or.GetToken());
  http_.InvalidateCache();
  co_return FileContext{.item = Item(source.item->account, std::move(item)),
                        .parent = destination.item};
}

auto FileSystemContext::CreateDirectory(const FileContext& context,
                                        std::string_view name,
                                        stdx::stop_token stop_token)
    -> Task<FileContext> {
  auto stop_token_or = GetToken(context, std::move(stop_token));
  auto new_directory = co_await context.item->provider().CreateDirectory(
      context.item->item, name, stop_token_or.GetToken());
  http_.InvalidateCache();
  co_return FileContext{
      .item = Item(context.item->account, std::move(new_directory)),
      .parent = context.item};
}

Task<> FileSystemContext::Remove(const FileContext& context,
                                 stdx::stop_token stop_token) {
  auto stop_token_or = GetToken(context, std::move(stop_token));
  if (!context.item) {
    throw CloudException("cannot remove root");
  }
  co_await context.item->provider().RemoveItem(context.item->item,
                                               stop_token_or.GetToken());
  http_.InvalidateCache();
}

auto FileSystemContext::Create(const FileContext& parent, std::string_view name,
                               stdx::stop_token stop_token)
    -> Task<FileContext> {
  if (config_.buffered_write ||
      (parent.item && !parent.item->provider().CanCreateFile<FileContent>(
                          parent.item->item))) {
    co_return co_await CreateBufferedUpload(parent, name,
                                            std::move(stop_token));
  }
  if (!parent.item) {
    throw CloudException("invalid parent");
  }
  co_return FileContext{
      .parent = parent.item,
      .current_streaming_write =
          std::make_unique<CurrentStreamingWrite>(*parent.item, name)};
}

Task<> FileSystemContext::Write(const FileContext& item, std::string_view chunk,
                                int64_t offset, stdx::stop_token stop_token) {
  if (item.current_write && item.current_write->tmpfile) {
    co_return co_await WriteToBufferedUpload(item, chunk, offset,
                                             std::move(stop_token));
  }
  if (!item.current_streaming_write) {
    if (item.item && item.item->GetGenericItem().size == 0 && item.parent) {
      item.current_streaming_write = std::make_unique<CurrentStreamingWrite>(
          *item.parent, item.item->GetGenericItem().name);
    } else {
      throw CloudException("streaming write missing");
    }
  }
  co_await item.current_streaming_write->Write(chunk, offset,
                                               std::move(stop_token));
}

auto FileSystemContext::Flush(const FileContext& item,
                              stdx::stop_token stop_token)
    -> Task<FileContext> {
  if (item.current_write && item.current_write->tmpfile) {
    co_return co_await FlushBufferedUpload(item, std::move(stop_token));
  }
  if (!item.current_streaming_write) {
    throw CloudException("streaming write missing");
  }
  auto new_item =
      co_await item.current_streaming_write->Flush(std::move(stop_token));
  http_.InvalidateCache();
  co_return FileContext{.item = std::move(new_item), .parent = item.parent};
}

auto FileSystemContext::CreateBufferedUpload(const FileContext& parent,
                                             std::string_view name,
                                             stdx::stop_token)
    -> Task<FileContext> {
  if (!parent.item) {
    throw CloudException("invalid parent");
  }
  co_return FileContext{
      .parent = parent.item,
      .current_write = CurrentWrite{.tmpfile = CreateTmpFile(),
                                    .new_name = std::string(name)}};
}

Task<> FileSystemContext::WriteToBufferedUpload(const FileContext& context,
                                                std::string_view chunk,
                                                int64_t offset,
                                                stdx::stop_token stop_token) {
  if (!context.current_write) {
    if (!context.item) {
      throw CloudException("invalid write");
    }
    auto stop_token_data =
        std::make_unique<StopTokenData>(context.item->stop_token());
    auto file = CreateTmpFile();
    NewFileRead read{.item = *context.item,
                     .file = file.get(),
                     .stop_token = stop_token_data->stop_token_or.GetToken()};
    context.current_write =
        CurrentWrite{.tmpfile = std::move(file),
                     .new_name = context.item->GetGenericItem().name,
                     .new_file_read = SharedPromise(std::move(read)),
                     .stop_token_data = std::move(stop_token_data)};
  }
  if (!context.parent) {
    throw CloudException("no parent");
  }

  StopTokenOr stop_token_or(std::move(stop_token),
                            context.parent->stop_token());
  if (context.current_write->new_file_read) {
    co_await context.current_write->new_file_read->Get(
        stop_token_or.GetToken());
  }

  auto file = context.current_write->tmpfile.get();
  if (fseek(file, static_cast<long>(offset), SEEK_SET) != 0) {
    throw CloudException("seek fail");
  }

  if (fwrite(chunk.data(), 1, chunk.size(), file) != chunk.size()) {
    throw CloudException("write fail");
  }

  co_return;
}

auto FileSystemContext::FlushBufferedUpload(const FileContext& item,
                                            stdx::stop_token stop_token)
    -> Task<FileContext> {
  if (!item.current_write) {
    throw CloudException("invalid flush");
  }
  if (!item.parent) {
    throw CloudException("invalid parent");
  }

  StopTokenOr stop_token_or(std::move(stop_token), item.parent->stop_token());
  if (item.current_write->new_file_read) {
    co_await item.current_write->new_file_read->Get(stop_token_or.GetToken());
  }

  struct RandomAccessFile {
    int64_t size;
    FILE* file;
    Task<std::string> operator()(int64_t offset, int64_t chunk_size,
                                 stdx::stop_token) const {
      fseek(file, offset, SEEK_SET);
      std::string buffer(chunk_size, 0);
      buffer.resize(fread(buffer.data(), 1, chunk_size, file));
      co_return std::move(buffer);
    }
  };

  auto file = item.current_write->tmpfile.get();
  auto new_item =
      item.parent->provider().CanCreateFile<FileContent>(item.parent->item)
          ? co_await item.parent->provider().CreateFile(
                item.parent->item, item.current_write->new_name,
                FileContent{.data = ReadFile(file), .size = GetFileSize(file)},
                stop_token_or.GetToken())
          : co_await item.parent->provider().CreateFile(
                item.parent->item, item.current_write->new_name,
                RandomAccessFile{.size = GetFileSize(file), .file = file},
                stop_token_or.GetToken());

  http_.InvalidateCache();
  co_return FileContext{.item = Item(item.parent->account, std::move(new_item)),
                        .parent = item.parent};
}

auto FileSystemContext::GetAccount(std::string_view name) const
    -> std::shared_ptr<CloudProviderAccount> {
  auto it = std::find_if(accounts_.begin(), accounts_.end(),
                         [name](auto d) { return d->id == name; });
  if (it == accounts_.end()) {
    throw CloudException(CloudException::Type::kNotFound);
  } else {
    return *it;
  }
}

Task<> FileSystemContext::Main() {
  CloudFactory cloud_factory(event_loop_, http_);
  http::HttpServer http_server(
      event_base_, {.address = "0.0.0.0", .port = 12345},
      AccountManagerHandlerT(cloud_factory, AccountListener{this}));
  co_await quit_;
  co_await http_server.Quit();
}

Task<> FileSystemContext::NewFileRead::operator()() {
  FOR_CO_AWAIT(std::string & chunk,
               item.provider().GetFileContent(item.item, http::Range{},
                                              std::move(stop_token))) {
    if (fwrite(chunk.data(), 1, chunk.size(), file) != chunk.size()) {
      throw CloudException("write fail");
    }
  }
}

FileSystemContext::CurrentStreamingWrite::CurrentStreamingWrite(
    Item parent, std::string_view name)
    : parent_(std::move(parent)),
      name_(name),
      stop_token_data_(parent_.stop_token()),
      create_file_task_(CreateFile()) {}

FileSystemContext::CurrentStreamingWrite::~CurrentStreamingWrite() {
  stop_token_data_.stop_source.request_stop();
}

Task<> FileSystemContext::CurrentStreamingWrite::Write(
    std::string_view chunk, int64_t offset, stdx::stop_token stop_token) {
  if (flushed_) {
    throw CloudException("write after flush");
  }
  if (current_offset_ != offset) {
    throw CloudException("write out of order");
  }
  current_offset_ += chunk.size();
  current_chunk_.SetValue(std::string(chunk));
  StopTokenOr stop_token_or(stop_token_data_.stop_token_or.GetToken(),
                            std::move(stop_token));
  co_await InterruptibleAwait(done_, stop_token_or.GetToken());
  done_ = Promise<void>();
}

auto FileSystemContext::CurrentStreamingWrite::Flush(
    stdx::stop_token stop_token) -> Task<Item> {
  if (flushed_) {
    throw CloudException("flush already called");
  }
  flushed_ = true;
  current_chunk_.SetValue(std::string());
  StopTokenOr stop_token_or(stop_token_data_.stop_token_or.GetToken(),
                            std::move(stop_token));
  co_return Item(parent_.account,
                 co_await InterruptibleAwait(std::move(create_file_task_),
                                             stop_token_or.GetToken()));
}

auto FileSystemContext::CurrentStreamingWrite::CreateFile()
    -> Task<AbstractCloudProviderT::Item> {
  try {
    co_return co_await parent_.provider().CreateFile(
        parent_.item, name_, FileContent{.data = GetStream()},
        stop_token_data_.stop_token_or.GetToken());
  } catch (...) {
    done_.SetException(std::current_exception());
    throw;
  }
}

Generator<std::string> FileSystemContext::CurrentStreamingWrite::GetStream() {
  while (!flushed_) {
    std::string chunk = co_await InterruptibleAwait(
        current_chunk_, stop_token_data_.stop_token_or.GetToken());
    current_chunk_ = Promise<std::string>();
    done_.SetValue();
    co_yield std::move(chunk);
  }
}

}  // namespace coro::cloudstorage