#ifndef CORO_CLOUDSTORAGE_FUSE_ITEM_CONTEXT_H
#define CORO_CLOUDSTORAGE_FUSE_ITEM_CONTEXT_H

#include "sparse_file.h"
#include "streaming_write.h"

namespace coro::cloudstorage::fuse {

template <typename CloudProvider>
class ItemContext {
 public:
  template <typename T>
  struct IsDirectoryT : std::bool_constant<IsDirectory<T, CloudProvider>> {};

  template <typename T>
  struct IsFileT : std::bool_constant<IsFile<T, CloudProvider>> {};

  using File = typename coro::util::FromTypeListT<
      std::variant,
      coro::util::FilterT<IsFileT, typename CloudProvider::ItemTypeList>>;

  using Directory = coro::util::FromTypeListT<
      std::variant,
      coro::util::FilterT<IsDirectoryT, typename CloudProvider::ItemTypeList>>;

  using Item = std::variant<File, Directory>;

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
  bool IsPending() const { return !item_; }

 private:
  template <typename>
  friend class FileSystemProvider;

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

  struct NewFileRead {
    Task<> operator()();

    CloudProvider* provider;
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

  template <typename T>
  struct CanCreateT : std::bool_constant<CanCreateFile<T, CloudProvider>> {};

  template <typename T>
  struct WriteT : std::type_identity<CurrentStreamingWrite<CloudProvider, T>> {
  };

  using CurrentStreamingWriteT = coro::util::FromTypeListT<
      std::variant,
      coro::util::MapT<
          WriteT, coro::util::FilterT<CanCreateT,
                                      typename CloudProvider::ItemTypeList>>>;

  std::optional<Item> item_;
  std::optional<Directory> parent_;
  mutable std::optional<CurrentRead> current_read_;
  mutable std::optional<CurrentWrite> current_write_;
  mutable std::unique_ptr<CurrentStreamingWriteT> current_streaming_write_;
  mutable stdx::stop_source stop_source_;
};

template <typename CloudProvider>
Task<> ItemContext<CloudProvider>::NewFileRead::operator()() {
  auto generator = std::visit(
      [&](const auto& d) {
        return provider->GetFileContent(d, http::Range{},
                                        std::move(stop_token));
      },
      item);
  FOR_CO_AWAIT(std::string & chunk, std::move(generator)) {
    if (co_await thread_pool->Invoke(fwrite, chunk.data(), 1, chunk.size(),
                                     file) != chunk.size()) {
      throw CloudException("write fail");
    }
  }
}

template <typename CloudProvider>
auto ItemContext<CloudProvider>::GetId() const -> std::string {
  if (!item_) {
    return "";
  }
  return std::visit(
      [](const auto& d) {
        return std::visit(
            [](const auto& d) {
              std::stringstream stream;
              stream << d.id;
              return std::move(stream).str();
            },
            d);
      },
      *item_);
}

template <typename CloudProvider>
auto ItemContext<CloudProvider>::GetTimestamp() const
    -> std::optional<int64_t> {
  if (!item_) {
    return std::nullopt;
  }
  return std::visit(
      [](const auto& d) {
        return std::visit(
            [](const auto& d) { return CloudProvider::GetTimestamp(d); }, d);
      },
      *item_);
}

template <typename CloudProvider>
auto ItemContext<CloudProvider>::GetSize() const -> std::optional<int64_t> {
  if (!item_) {
    return std::nullopt;
  }
  return std::visit(
      [](const auto& d) {
        return std::visit(
            [](const auto& d) { return CloudProvider::GetSize(d); }, d);
      },
      *item_);
}

template <typename CloudProvider>
auto ItemContext<CloudProvider>::GetType() const -> ItemType {
  if (!item_) {
    return ItemType::kFile;
  }
  return std::holds_alternative<Directory>(*item_) ? ItemType::kDirectory
                                                   : ItemType::kFile;
}

template <typename CloudProvider>
std::string ItemContext<CloudProvider>::GetName() const {
  if (!item_) {
    return "";
  }
  return std::visit(
      [](const auto& d) {
        return std::visit([](const auto& d) { return d.name; }, d);
      },
      *item_);
}

}  // namespace coro::cloudstorage::fuse

#endif  // CORO_CLOUDSTORAGE_FUSE_ITEM_CONTEXT_H
