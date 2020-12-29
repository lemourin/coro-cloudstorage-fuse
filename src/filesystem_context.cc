#include "filesystem_context.h"

#include <coro/cloudstorage/cloud_exception.h>
#include <coro/http/http_server.h>

namespace coro::cloudstorage::internal {

namespace {

constexpr std::string_view kTokenFile = "access-token.json";

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
FileSystemContext<TypeList<T...>>::FileSystemContext()
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

template <typename... T>
FileSystemContext<TypeList<T...>>::~FileSystemContext() {
  event_base_once(
      event_loop_.get(), -1, EV_TIMEOUT,
      [](evutil_socket_t, short, void* d) {
        reinterpret_cast<FileSystemContext*>(d)->quit_.SetValue();
      },
      this, nullptr);
  thread_.join();
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
auto FileSystemContext<TypeList<T...>>::GetFileContext(std::string path) const
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
  co_return co_await std::visit(
      [=](auto& d) -> Task<std::variant<ItemT<T>...>> {
        using CloudProvider = std::remove_cvref_t<decltype(d)>;
        co_return Item<CloudProvider>(account,
                                      co_await d.GetItemByPath(provider_path));
      },
      account->provider);
}

template <typename... T>
auto FileSystemContext<TypeList<T...>>::ReadDirectory(
    const FileContext& context) const -> Generator<std::vector<FileContext>> {
  if (!context.item) {
    std::vector<FileContext> result;
    for (auto account : accounts_) {
      auto root = co_await std::visit(
          [](auto& provider) -> Task<std::variant<typename T::Directory...>> {
            co_return co_await provider.GetRoot();
          },
          account->provider);
      std::visit([id = account->id](
                     auto& directory) { directory.name = std::move(id); },
                 root);
      result.emplace_back(std::make_optional(std::visit(
          [&](auto& provider) -> std::variant<ItemT<T>...> {
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
                std::get<typename CloudProviderT::Directory>(d.item))) {
          std::vector<FileContext> page;
          for (auto& item : page_data.items) {
            page.emplace_back(Item<CloudProviderT>(d.account, std::move(item)));
          }
          co_yield std::move(page);
        }
      },
      *context.item);

  FOR_CO_AWAIT(std::vector<FileContext> & page_data, generator) {
    co_yield std::move(page_data);
  }
}

template <typename... T>
auto FileSystemContext<TypeList<T...>>::GetVolumeData() const
    -> Task<VolumeData> {
  using AnyTask = std::variant<Task<typename T::GeneralData>...>;
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
          if constexpr (HasUsageData<decltype(data)>) {
            co_return VolumeData{.space_used = data.space_used,
                                 .space_total = data.space_total};
          } else {
            co_return VolumeData{.space_used = 0, .space_total = 0};
          }
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

template <typename... T>
Task<std::string> FileSystemContext<TypeList<T...>>::Read(
    const FileContext& context, int64_t offset, int64_t size) const {
  if (!context.item) {
    throw CloudException("not a file");
  }
  auto generic_item = GetGenericItem(context);
  if (!generic_item.size) {
    throw CloudException("size unknown");
  }
  size = std::min<int64_t>(size, *generic_item.size - offset);
  std::cerr << "READ " << offset << " " << size << " " << generic_item.name
            << "\n";
  auto current_read = std::exchange(context.current_read, std::nullopt);
  if (!current_read || current_read->offset != offset) {
    std::cerr << "STARTING READ " << offset << "\n";
    using CurrentRead = typename FileContext::CurrentRead;
    auto generator = std::visit(
        [=](const auto& d) {
          using CloudProviderT =
              typename std::remove_cvref_t<decltype(d)>::CloudProvider;
          const auto& item = std::get<typename CloudProviderT::File>(d.item);
          return d.provider()->GetFileContent(item,
                                              http::Range{.start = offset});
        },
        *context.item);
    auto it = co_await generator.begin();
    current_read =
        CurrentRead{.generator = std::move(generator), .it = std::move(it)};
  } else {
    std::cerr << "REUSING READ\n";
  }
  std::string chunk = std::exchange(current_read->chunk, "");
  while (static_cast<int64_t>(chunk.size()) < size &&
         current_read->it != std::end(current_read->generator)) {
    chunk += std::move(*current_read->it);
    co_await ++current_read->it;
  }
  current_read->offset = offset + size;
  if (static_cast<int64_t>(chunk.size()) > size) {
    current_read->chunk = std::string(chunk.begin() + size, chunk.end());
    chunk.resize(size);
  }
  context.current_read = std::move(current_read);
  co_return std::move(chunk);
}  // namespace coro::cloudstorage::internal

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
void FileSystemContext<TypeList<T...>>::Main() {
  Invoke(CoMain(event_loop_.get()));
  event_base_dispatch(event_loop_.get());
}

template <typename... T>
Task<> FileSystemContext<TypeList<T...>>::CoMain(event_base* event_base) {
  try {
    Http http{http::CurlHttp(event_base)};
    EventLoop event_loop(event_base);
    CloudFactory cloud_factory(event_loop, http);
    http::HttpServer http_server(
        event_base, {.address = "0.0.0.0", .port = 12345},
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

template class FileSystemContext<CloudProviders>;

}  // namespace coro::cloudstorage::internal