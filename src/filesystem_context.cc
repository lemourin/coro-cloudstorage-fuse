#include "filesystem_context.h"

#include <coro/cloudstorage/cloud_exception.h>
#include <coro/http/http_server.h>
#include <coro/util/stop_token_or.h>

namespace coro::cloudstorage::internal {

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

template <typename FileSystemContext, typename ItemT, typename Directory,
          typename PageData = typename FileSystemContext::PageData,
          typename FileContext = typename FileSystemContext::FileContext>
Task<PageData> GetPage(ItemT d, Directory directory,
                       std::optional<std::string> page_token,
                       stdx::stop_token stop_token) {
  auto page_data = co_await d.provider()->ListDirectoryPage(
      std::move(directory), std::move(page_token), std::move(stop_token));
  PageData page{.next_page_token = page_data.next_page_token};
  for (auto& item : page_data.items) {
    page.items.emplace_back(
        FileContext{.item = ItemT(d.account, std::move(item))});
  }
  co_return std::move(page);
}

template <typename FileContext>
StopTokenOr GetToken(const FileContext& context, stdx::stop_token stop_token) {
  if (!context.item) {
    throw std::invalid_argument("item not associated with any account");
  }

  return StopTokenOr(
      std::move(stop_token),
      std::visit(
          [&](const auto& d) {
            auto acc = d.account.lock();
            if (!acc) {
              throw CloudException(CloudException::Type::kNotFound);
            }
            return acc->stop_source.get_token();
          },
          *context.item));
}

}  // namespace

template <typename... T>
void FileSystemContext<TypeList<T...>>::AccountListener::OnCreate(
    CloudProviderAccount* d) {
  context->accounts_.insert(
      std::shared_ptr<CloudProviderAccount>(d, [](auto) {}));
  std::cerr << "CREATED " << d->id << "\n";
}

template <typename... T>
void FileSystemContext<TypeList<T...>>::AccountListener::OnDestroy(
    CloudProviderAccount* d) {
  context->accounts_.erase(
      std::shared_ptr<CloudProviderAccount>(d, [](auto) {}));
  std::cerr << "REMOVED " << d->id << "\n";
}

template <typename... T>
FileSystemContext<TypeList<T...>>::FileSystemContext(event_base* event_base)
    : event_base_(event_base),
      event_loop_(event_base_),
      http_(http::CurlHttp(event_base)) {
  Invoke(Main());
}

template <typename... T>
FileSystemContext<TypeList<T...>>::~FileSystemContext() {
  Quit();
}

template <typename... T>
void FileSystemContext<TypeList<T...>>::Cancel() {
  for (const auto& account : accounts_) {
    account->stop_source.request_stop();
  }
}

template <typename... T>
void FileSystemContext<TypeList<T...>>::Quit() {
  if (!quit_called_) {
    quit_called_ = true;
    Cancel();
    quit_.SetValue();
  }
}

template <typename... T>
auto FileSystemContext<TypeList<T...>>::GetGenericItem(const FileContext& ctx)
    -> GenericItem {
  if (!ctx.item) {
    return GenericItem{.name = "root", .is_directory = true};
  }
  return std::visit([](const auto& d) { return d.GetGenericItem(); },
                    *ctx.item);
}

template <typename... T>
auto FileSystemContext<TypeList<T...>>::GetFileContext(
    std::string path, stdx::stop_token stop_token) const -> Task<FileContext> {
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
        using CloudProvider = std::remove_cvref_t<decltype(d)>;
        co_return FileContext{
            .item = Item<CloudProvider>(
                account, co_await d.GetItemByPath(provider_path,
                                                  stop_token_or.GetToken()))};
      },
      account->provider);
}

template <typename... T>
template <typename D>
auto FileSystemContext<TypeList<T...>>::GetDirectoryPage::operator()(
    const D& d) const -> Task<PageData> {
  return std::visit(
      [d, page_token = std::move(page_token),
       stop_token =
           std::move(stop_token)](const auto& directory) -> Task<PageData> {
        using CloudProviderT = typename D::CloudProviderT;
        if constexpr (IsDirectory<decltype(directory), CloudProviderT>) {
          return GetPage<FileSystemContext>(d, directory, std::move(page_token),
                                            std::move(stop_token));
        } else {
          throw std::invalid_argument("not a directory");
        }
      },
      d.item);
}

template <typename... T>
auto FileSystemContext<TypeList<T...>>::ReadDirectory(
    const FileContext& context, stdx::stop_token stop_token) const
    -> Generator<std::vector<FileContext>> {
  std::optional<std::string> page_token;
  do {
    auto page_data =
        co_await ReadDirectoryPage(context, std::move(page_token), stop_token);
    page_token = std::move(page_data.next_page_token);
    co_yield std::move(page_data.items);
  } while (page_token);
}

template <typename... T>
auto FileSystemContext<TypeList<T...>>::ReadDirectoryPage(
    const FileContext& context, std::optional<std::string> page_token,
    stdx::stop_token stop_token) const -> Task<PageData> {
  if (!context.item) {
    std::vector<FileContext> result;
    for (auto account : accounts_) {
      auto root = co_await std::visit(
          [&](auto& provider) -> Task<FileContext> {
            using CloudProviderT = std::remove_cvref_t<decltype(provider)>;
            FileContext context = {};
            auto directory = co_await provider.GetRoot(std::move(stop_token));
            directory.name = account->id;
            context.item = Item<CloudProviderT>(account, std::move(directory));
            co_return context;
          },
          account->provider);
      result.emplace_back(std::move(root));
    }
    co_return PageData{.items = std::move(result)};
  }

  auto stop_token_or = GetToken(context, std::move(stop_token));
  co_return co_await std::visit(
      GetDirectoryPage{std::move(page_token), stop_token_or.GetToken()},
      *context.item);
}

template <typename... T>
auto FileSystemContext<TypeList<T...>>::GetVolumeData(
    stdx::stop_token stop_token) const -> Task<VolumeData> {
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

template <typename... T>
Task<std::string> FileSystemContext<TypeList<T...>>::Read(
    const FileContext& context, int64_t offset, int64_t size,
    stdx::stop_token stop_token) const {
  using QueuedRead = typename FileContext::QueuedRead;

  auto stop_token_or = GetToken(context, std::move(stop_token));
  if (!context.item) {
    throw CloudException("not a file");
  }
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
      struct AwaiterGuard {
        void operator()() {
          context->queued_reads.erase(std::find(context->queued_reads.begin(),
                                                context->queued_reads.end(),
                                                queued_read));
        }
        const FileContext* context;
        const QueuedRead* queued_read;
      };
      QueuedRead queued_read{.offset = offset, .size = size};
      auto awaiter_guard = AtScopeExit(
          AwaiterGuard{.context = &context, .queued_read = &queued_read});
      context.queued_reads.emplace_back(&queued_read);
      co_await queued_read.awaiter;
    }
  }
  try {
    if (!current_read || current_read->current_offset != offset) {
      std::cerr << "STARTING READ " << generic_item.name << " " << offset
                << "\n";
      using CurrentRead = typename FileContext::CurrentRead;
      auto generator = std::visit(
          [&](const auto& d) {
            using CloudProviderT =
                typename std::remove_cvref_t<decltype(d)>::CloudProviderT;
            return std::visit(
                [&](const auto& item) -> Generator<std::string> {
                  if constexpr (IsFile<decltype(item), CloudProviderT>) {
                    return d.provider()->GetFileContent(
                        item, http::Range{.start = offset},
                        stop_token_or.GetToken());
                  } else {
                    throw std::invalid_argument("not a file");
                  }
                },
                d.item);
          },
          *context.item);
      current_read = CurrentRead{.generator = std::move(generator),
                                 .current_offset = offset,
                                 .pending = true};
      current_read->it = co_await current_read->generator.begin();
    } else {
      current_read->pending = true;
    }
    std::string chunk = std::exchange(current_read->chunk, "");
    while (static_cast<int64_t>(chunk.size()) < size &&
           *current_read->it != std::end(current_read->generator)) {
      chunk += std::move(**current_read->it);
      co_await ++*current_read->it;
    }
    current_read->current_offset = offset + size;
    if (static_cast<int64_t>(chunk.size()) > size) {
      current_read->chunk = std::string(chunk.begin() + size, chunk.end());
      chunk.resize(size);
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

template <typename... T>
auto FileSystemContext<TypeList<T...>>::Rename(const FileContext& item,
                                               std::string_view new_name,
                                               stdx::stop_token stop_token)
    -> Task<FileContext> {
  if (!item.item) {
    throw CloudException("cannot rename root");
  }

  auto stop_token_or = GetToken(item, std::move(stop_token));
  co_return co_await std::visit(
      [&http = http_, new_name, stop_token = stop_token_or.GetToken()](
          auto& p) mutable -> Task<FileContext> {
        using CloudProviderT =
            typename std::remove_cvref_t<decltype(p)>::CloudProviderT;
        auto item = co_await p.provider()->RenameItem(
            p.item, std::string(new_name), std::move(stop_token));
        http.InvalidateCache();
        co_return FileContext{
            .item = Item<CloudProviderT>(p.account, std::move(item))};
      },
      *item.item);
}

template <typename... T>
auto FileSystemContext<TypeList<T...>>::CreateDirectory(
    const FileContext& item, std::string_view name, stdx::stop_token stop_token)
    -> Task<FileContext> {
  auto stop_token_or = GetToken(item, std::move(stop_token));
  co_return co_await std::visit(
      [&http = http_, name, stop_token = stop_token_or.GetToken()](
          auto& p) mutable -> Task<FileContext> {
        using CloudProviderT =
            typename std::remove_cvref_t<decltype(p)>::CloudProviderT;
        auto new_directory = co_await std::visit(
            [&](auto& d) -> Task<FileContext> {
              if constexpr (IsDirectory<decltype(d), CloudProviderT>) {
                auto new_directory = co_await p.provider()->CreateDirectory(
                    d, std::string(name), std::move(stop_token));
                co_return FileContext{.item = Item<CloudProviderT>(
                                          p.account, std::move(new_directory))};
              } else {
                throw std::invalid_argument("not a directory");
              }
            },
            p.item);
        http.InvalidateCache();
        co_return std::move(new_directory);
      },
      *item.item);
}

template <typename... T>
Task<> FileSystemContext<TypeList<T...>>::Remove(const FileContext& item,
                                                 stdx::stop_token stop_token) {
  auto stop_token_or = GetToken(item, std::move(stop_token));
  co_await std::visit(
      [&http = http_,
       stop_token = stop_token_or.GetToken()](auto& p) mutable -> Task<> {
        using CloudProviderT =
            typename std::remove_cvref_t<decltype(p)>::CloudProviderT;
        co_await p.provider()->RemoveItem(p.item, std::move(stop_token));
        http.InvalidateCache();
      },
      *item.item);
}

template <typename... T>
auto FileSystemContext<TypeList<T...>>::GetAccount(std::string_view name) const
    -> std::shared_ptr<CloudProviderAccount> {
  auto it = std::find_if(accounts_.begin(), accounts_.end(),
                         [name](auto d) { return d->id == name; });
  if (it == accounts_.end()) {
    throw CloudException(CloudException::Type::kNotFound);
  } else {
    return *it;
  }
}

template <typename... T>
Task<> FileSystemContext<TypeList<T...>>::Main() {
  CloudFactory cloud_factory(event_loop_, http_);
  http::HttpServer http_server(
      event_base_, {.address = "0.0.0.0", .port = 12345},
      AccountManagerHandlerT(cloud_factory, AccountListener{this}));
  co_await quit_;
  co_await http_server.Quit();
}

template class FileSystemContext<CloudProviders>;

}  // namespace coro::cloudstorage::internal