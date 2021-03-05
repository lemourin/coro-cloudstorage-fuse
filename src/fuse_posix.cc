#include "fuse_posix.h"

#define FUSE_USE_VERSION 39
#include <coro/util/function_traits.h>
#include <coro/util/raii_utils.h>
#include <event2/thread.h>
#include <fuse.h>
#include <fuse_lowlevel.h>

#include <csignal>
#include <iostream>

#include "filesystem_context.h"

namespace coro::cloudstorage::fuse {

namespace {

using ::coro::util::AtScopeExit;

using FileContext = FileSystemContext::FileContext;

constexpr int kIndexWidth = sizeof(off_t) * CHAR_BIT / 2;
constexpr int kMetadataTimeout = 10;

struct ReadDirToken {
  off_t page_index;
  off_t offset;
};

ReadDirToken DecodeReadDirToken(off_t d) {
  return ReadDirToken{.page_index = d >> kIndexWidth,
                      .offset = d & ((1ll << kIndexWidth) - 1)};
}

off_t EncodeReadDirToken(ReadDirToken token) {
  return (token.page_index << kIndexWidth) | token.offset;
}

struct Flush {
  struct Callback {
    Task<> operator()() const { co_await* done; }
    Promise<void>* done;
  };

  Flush() : promise(Callback{.done = &done}) {}

  int pending_count = 0;
  Promise<void> done;
  SharedPromise<Callback> promise;
};

struct ItemId {
  size_t account_type;
  std::string account_id;
  std::string item_id;

  bool operator==(const ItemId& other) const {
    return std::tie(account_type, account_id, item_id) ==
           std::tie(other.account_type, other.account_id, other.item_id);
  }
};

struct ItemIdHash {
  auto operator()(const ItemId& id) const {
    return std::hash<size_t>{}(id.account_type) +
           std::hash<std::string>{}(id.account_id) +
           std::hash<std::string>{}(id.item_id);
  }
};

struct FuseFileContext {
  FileContext context;
  fuse_ino_t parent;
  int flags;
  int64_t refcount;
  std::vector<std::string> page_token = {""};
  std::unique_ptr<Flush> flush;
  std::optional<int64_t> size;
  std::optional<std::string> name;
  std::optional<ItemId> id;
};

struct FuseContext {
  std::unordered_map<fuse_ino_t, FuseFileContext> file_context;
  std::unordered_map<ItemId, fuse_ino_t, ItemIdHash> inode;
  FileSystemContext context;
  int next_inode = FUSE_ROOT_ID + 1;
  fuse_conn_info_opts* conn_opts;
};

struct EventBaseDeleter {
  void operator()(event_base* event_base) const {
    if (event_base) {
      event_base_free(event_base);
    }
  }
};

struct FuseSessionDeleter {
  void operator()(fuse_session* fuse_session) const {
    if (fuse_session) {
      fuse_session_destroy(fuse_session);
    }
  }
};

struct FreeDeleter {
  template <typename T>
  void operator()(T* d) const {
    free(d);
  }
};

void Check(int d) {
  if (d != 0) {
    throw std::runtime_error(strerror(d));
  }
}

void CheckEvent(int d) {
  if (d != 0) {
    throw std::runtime_error("libevent error");
  }
}

int ToPosixError(const CloudException& e) {
  switch (e.type()) {
    case CloudException::Type::kNotFound:
      return ENOENT;
    case CloudException::Type::kUnauthorized:
      return EACCES;
    default:
      return EIO;
  }
}

template <auto F, typename>
struct Coroutine;

template <auto F, typename... Args>
struct Coroutine<F, coro::util::TypeList<fuse_req_t, Args...>> {
  static void Do(fuse_req_t req, Args... args) {
    coro::Invoke([req, args...]() -> Task<> {
      try {
        co_await F(req, args...);
      } catch (const CloudException& e) {
        if (e.type() != CloudException::Type::kNotFound) {
          std::cerr << "ERROR:  " << e.what() << "\n";
        }
        fuse_reply_err(req, ToPosixError(e));
      } catch (const InterruptedException&) {
        fuse_reply_err(req, ECANCELED);
      } catch (const std::exception& e) {
        std::cerr << "ERROR " << e.what() << "\n";
        fuse_reply_err(req, EIO);
      }
    });
  }
};

template <auto F>
constexpr auto CoroutineT =
    Coroutine<F, coro::util::ArgumentListTypeT<decltype(F)>>::Do;

ItemId GetItemId(const FileContext& context) {
  return ItemId{.account_type = context.item->provider().type(),
                .account_id = context.item->GetAccount()->id,
                .item_id = FileSystemContext::GetGenericItem(context).id};
}

fuse_ino_t CreateNode(FuseContext* context, fuse_ino_t parent,
                      FileContext file_context) {
  if (!file_context.item) {
    throw std::invalid_argument("invalid context");
  }
  auto item_id = GetItemId(file_context);
  if (auto it = context->inode.find(item_id); it != std::end(context->inode)) {
    context->file_context[it->second].context = std::move(file_context);
    return it->second;
  } else {
    context->inode.emplace(item_id, context->next_inode);
    context->file_context[context->next_inode] = FuseFileContext{
        .context = std::move(file_context), .parent = parent, .id = item_id};
    return context->next_inode++;
  }
}

Task<FileContext> FindFile(FuseContext* context, const FuseFileContext& parent,
                           std::string_view name, stdx::stop_token stop_token) {
  if (parent.flush) {
    co_await parent.flush->promise.Get(stop_token);
  }
  FOR_CO_AWAIT(
      std::vector<FileContext> & page,
      context->context.ReadDirectory(parent.context, std::move(stop_token))) {
    for (FileContext& file_context : page) {
      if (name == FileSystemContext::GetGenericItem(file_context).name) {
        co_return std::move(file_context);
      }
    }
  }
  throw CloudException(CloudException::Type::kNotFound);
}

struct stat ToStat(const FileSystemContext::GenericItem& item) {
  struct stat stat = {};
  stat.st_mode = (item.type == FileSystemContext::GenericItem::Type::kDirectory
                      ? S_IFDIR
                      : S_IFREG) |
                 0644;
  stat.st_size = item.size.value_or(0);
  stat.st_mtim.tv_sec = item.timestamp.value_or(0);
  return stat;
}

fuse_entry_param CreateFuseEntry(FuseContext* context, fuse_ino_t parent,
                                 FileContext entry) {
  auto item = FileSystemContext::GetGenericItem(entry);
  fuse_entry_param fuse_entry = {};
  fuse_entry.attr = ToStat(item);
  fuse_entry.attr.st_ino = CreateNode(context, parent, std::move(entry));
  context->file_context[fuse_entry.attr.st_ino].refcount++;
  fuse_entry.attr_timeout = kMetadataTimeout;
  fuse_entry.entry_timeout = kMetadataTimeout;
  fuse_entry.generation = 1;
  fuse_entry.ino = fuse_entry.attr.st_ino;
  return fuse_entry;
}

void InterruptRequest(fuse_req_t, void* user_data) {
  reinterpret_cast<stdx::stop_source*>(user_data)->request_stop();
}

void Init(void* user_data, struct fuse_conn_info* conn) {
  auto context = reinterpret_cast<FuseContext*>(user_data);
  fuse_apply_conn_info_opts(context->conn_opts, conn);
}

void Destroy(void* user_data) {}

Task<> GetAttr(fuse_req_t req, fuse_ino_t ino, fuse_file_info*) {
  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  auto it = context->file_context.find(ino);
  if (it == context->file_context.end()) {
    fuse_reply_err(req, ENOENT);
    co_return;
  }
  if (it->second.flush) {
    stdx::stop_source stop_source;
    fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
    const auto& promise = it->second.flush->promise;
    co_await promise.Get(stop_source.get_token());
  }
  struct stat stat {};
  if (ino == FUSE_ROOT_ID || it->second.context.item) {
    stat = ToStat(FileSystemContext::GetGenericItem(it->second.context));
    stat.st_ino = ino;
  } else {
    stat.st_mode = S_IFREG | 0644;
  }
  if (it->second.size) {
    stat.st_size = *it->second.size;
  }
  fuse_reply_attr(req, &stat, kMetadataTimeout);
}

Task<> SetAttr(fuse_req_t req, fuse_ino_t ino, struct stat* attr, int to_set,
               fuse_file_info* fi) {
  if ((to_set & ~FUSE_SET_ATTR_SIZE) != 0) {
    fuse_reply_err(req, EINVAL);
    co_return;
  }
  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  auto it = context->file_context.find(ino);
  if (it == context->file_context.end()) {
    fuse_reply_err(req, ENOENT);
    co_return;
  }
  auto* file_context =
      fi ? reinterpret_cast<FuseFileContext*>(fi->fh) : &it->second;
  auto item = FileSystemContext::GetGenericItem(file_context->context);
  struct stat stat = ToStat(item);
  if (to_set & FUSE_SET_ATTR_SIZE) {
    if (attr->st_size == 0) {
      auto parent_it = context->file_context.find(file_context->parent);
      if (parent_it == context->file_context.end()) {
        fuse_reply_err(req, ENOENT);
        co_return;
      }
      stdx::stop_source stop_source;
      fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
      file_context->context = co_await context->context.Flush(
          co_await context->context.Create(parent_it->second.context, item.name,
                                           /*size=*/0, stop_source.get_token()),
          stop_source.get_token());
      if (fi) {
        it->second.context.item = file_context->context.item;
      }
    }
    it->second.size = attr->st_size;
  }
  fuse_reply_attr(req, &stat, kMetadataTimeout);
}

Task<> Open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi) {
  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  auto it = context->file_context.find(ino);
  if (it == context->file_context.end()) {
    fuse_reply_err(req, ENOENT);
    co_return;
  }
  if (it->second.flush) {
    stdx::stop_source stop_source;
    fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
    const auto& promise = it->second.flush->promise;
    co_await promise.Get(stop_source.get_token());
  }
  fi->fh = reinterpret_cast<uint64_t>(new FuseFileContext{
      .context = FileContext{.item = it->second.context.item,
                             .parent = it->second.context.parent},
      .parent = it->second.parent,
      .flags = fi->flags});
  if (fuse_reply_open(req, fi) != 0) {
    delete reinterpret_cast<FuseFileContext*>(fi->fh);
  }
}

Task<> OpenDir(fuse_req_t req, fuse_ino_t ino, fuse_file_info* fi) {
  return Open(req, ino, fi);
}

Task<> Release(fuse_req_t req, fuse_ino_t ino, fuse_file_info* fi) {
  std::unique_ptr<FuseFileContext> file_context(
      reinterpret_cast<FuseFileContext*>(fi->fh));
  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  if (!(file_context->flags & (O_RDWR | O_WRONLY))) {
    fuse_reply_err(req, 0);
    co_return;
  }
  stdx::stop_source stop_source;
  fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
  if (!file_context->context.current_write &&
      !file_context->context.current_streaming_write && file_context->name) {
    auto parent_it = context->file_context.find(file_context->parent);
    if (parent_it == context->file_context.end()) {
      fuse_reply_err(req, ENOENT);
      co_return;
    }
    file_context->context = co_await context->context.Create(
        parent_it->second.context, *file_context->name, 0,
        stop_source.get_token());
  }
  if (file_context->context.current_write ||
      file_context->context.current_streaming_write) {
    auto it = context->file_context.find(ino);
    if (it == std::end(context->file_context)) {
      fuse_reply_err(req, ENOENT);
      co_return;
    }
    auto parent_it = context->file_context.find(file_context->parent);
    auto guard = AtScopeExit([&] {
      if (parent_it != std::end(context->file_context)) {
        parent_it->second.flush->pending_count--;
        if (parent_it->second.flush->pending_count == 0) {
          parent_it->second.flush->done.SetValue();
          parent_it->second.flush = nullptr;
        }
      }
    });
    if (parent_it != std::end(context->file_context)) {
      if (!parent_it->second.flush) {
        parent_it->second.flush = std::make_unique<Flush>();
      }
      parent_it->second.flush->pending_count++;
    }
    it->second.flush = std::make_unique<Flush>();
    try {
      auto new_item = co_await context->context.Flush(file_context->context,
                                                      stop_source.get_token());
      auto new_id = GetItemId(new_item);
      context->inode.emplace(new_id, ino);
      it->second.context = std::move(new_item);
      it->second.id = std::move(new_id);
      it->second.flush->done.SetValue();
    } catch (...) {
      it->second.flush->done.SetException(std::current_exception());
    }
  }
  fuse_reply_err(req, 0);
}

Task<> ReleaseDir(fuse_req_t req, fuse_ino_t ino, fuse_file_info* fi) {
  return Release(req, ino, fi);
}

Task<> ReadDir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
               fuse_file_info* fi) {
  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  auto it = context->file_context.find(ino);
  if (it == context->file_context.end()) {
    fuse_reply_err(req, ENOENT);
    co_return;
  }
  auto& file_context = *reinterpret_cast<FuseFileContext*>(fi->fh);
  if (file_context.page_token.size() > 1 &&
      file_context.page_token.back().empty()) {
    fuse_reply_buf(req, nullptr, 0);
    co_return;
  }
  ReadDirToken read_dir_token = DecodeReadDirToken(off);
  if (read_dir_token.page_index >= file_context.page_token.size()) {
    fuse_reply_err(req, EINVAL);
    co_return;
  }
  std::string buffer(size, 0);
  int offset = 0;
  int current_index = 0;
  stdx::stop_source stop_source;
  fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
  if (it->second.flush) {
    const auto& promise = it->second.flush->promise;
    co_await promise.Get(stop_source.get_token());
  }
  auto page = co_await context->context.ReadDirectoryPage(
      file_context.context,
      read_dir_token.page_index == 0
          ? std::nullopt
          : std::make_optional(
                file_context.page_token[read_dir_token.page_index]),
      stop_source.get_token());
  for (int i = read_dir_token.offset; i < page.items.size(); i++) {
    FileContext& entry = page.items[i];
    auto generic_item = FileSystemContext::GetGenericItem(entry);
    fuse_entry_param fuse_entry = {};
    fuse_entry.attr = ToStat(generic_item);
    fuse_entry.attr.st_ino = CreateNode(context, ino, std::move(entry));
    fuse_entry.generation = 1;
    fuse_entry.ino = fuse_entry.attr.st_ino;
    fuse_entry.attr_timeout = kMetadataTimeout;
    fuse_entry.entry_timeout = kMetadataTimeout;
    auto entry_size = fuse_add_direntry_plus(
        req, nullptr, 0, generic_item.name.c_str(), nullptr, 0);
    if (offset + entry_size < size) {
      context->file_context[fuse_entry.ino].refcount++;
      ReadDirToken next_token;
      if (i + 1 == page.items.size()) {
        next_token = {.page_index = read_dir_token.page_index + 1, .offset = 0};
        if (read_dir_token.page_index + 1 >= file_context.page_token.size()) {
          file_context.page_token.emplace_back(
              page.next_page_token.value_or(""));
        }
      } else {
        next_token = {.page_index = read_dir_token.page_index, .offset = i + 1};
      }
      offset += fuse_add_direntry_plus(
          req, buffer.data() + offset, size - offset, generic_item.name.c_str(),
          &fuse_entry, EncodeReadDirToken(next_token));
    } else {
      break;
    }
    current_index++;
  }
  fuse_reply_buf(req, buffer.data(), offset);
}

Task<> Lookup(fuse_req_t req, fuse_ino_t parent, const char* name_c_str) {
  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  auto it = context->file_context.find(parent);
  if (it == context->file_context.end()) {
    fuse_reply_err(req, ENOENT);
    co_return;
  }
  auto& file_context = it->second;
  stdx::stop_source stop_source;
  fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
  std::string name = name_c_str;
  auto entry =
      co_await FindFile(context, file_context, name, stop_source.get_token());
  fuse_entry_param fuse_entry =
      CreateFuseEntry(context, parent, std::move(entry));
  fuse_reply_entry(req, &fuse_entry);
}

void Forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup) {
  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  auto it = context->file_context.find(ino);
  if (it == context->file_context.end()) {
    fuse_reply_none(req);
    return;
  }
  it->second.refcount -= nlookup;
  if (it->second.refcount == 0) {
    if (it->second.id) {
      context->inode.erase(*it->second.id);
    }
    context->file_context.erase(it);
  }
  fuse_reply_none(req);
}

Task<> Read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
            struct fuse_file_info* fi) {
  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  auto it = context->file_context.find(ino);
  if (it == context->file_context.end()) {
    fuse_reply_err(req, ENOENT);
    co_return;
  }
  auto file_context = reinterpret_cast<FuseFileContext*>(fi->fh);
  stdx::stop_source stop_source;
  fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
  auto data = co_await context->context.Read(file_context->context, off, size,
                                             stop_source.get_token());
  fuse_reply_buf(req, data.data(), data.size());
}

Task<> Rename(fuse_req_t req, fuse_ino_t parent, const char* name_c_str,
              fuse_ino_t new_parent, const char* new_name_c_str,
              unsigned int flags) {
  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  auto it_parent = context->file_context.find(parent);
  if (it_parent == context->file_context.end()) {
    fuse_reply_err(req, ENOENT);
    co_return;
  }

  std::string name = name_c_str;
  std::string new_name = new_name_c_str;
  stdx::stop_source stop_source;
  fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
  auto source_item = co_await FindFile(context, it_parent->second, name,
                                       stop_source.get_token());
  auto previous_id = GetItemId(source_item);

  FileContext new_item = {.item = source_item.item};
  if (name != new_name) {
    new_item = co_await context->context.Rename(source_item, new_name,
                                                stop_source.get_token());
  }

  if (parent != new_parent) {
    auto it_new_parent = context->file_context.find(new_parent);
    if (it_new_parent == context->file_context.end()) {
      fuse_reply_err(req, ENOENT);
      co_return;
    }
    new_item = co_await context->context.Move(
        new_item, it_new_parent->second.context, stop_source.get_token());
  }

  if (auto it = context->inode.find(previous_id);
      it != std::end(context->inode)) {
    auto inode = it->second;
    auto new_id = GetItemId(new_item);
    context->inode.erase(it);
    context->inode.emplace(new_id, inode);
    auto& file_context = context->file_context[inode];
    file_context.context = std::move(new_item);
    file_context.id = std::move(new_id);
    file_context.parent = parent;
  }
  fuse_reply_err(req, 0);
}

Task<> MkDir(fuse_req_t req, fuse_ino_t parent, const char* name, mode_t mode) {
  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  auto it = context->file_context.find(parent);
  if (it == context->file_context.end()) {
    fuse_reply_err(req, ENOENT);
    co_return;
  }

  stdx::stop_source stop_source;
  fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
  auto new_directory = co_await context->context.CreateDirectory(
      it->second.context, std::string(name), stop_source.get_token());

  fuse_entry_param entry =
      CreateFuseEntry(context, parent, std::move(new_directory));
  fuse_reply_entry(req, &entry);
}

Task<> Create(fuse_req_t req, fuse_ino_t parent, const char* name, mode_t mode,
              struct fuse_file_info* fi) {
  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  auto parent_it = context->file_context.find(parent);
  if (parent_it == context->file_context.end()) {
    fuse_reply_err(req, ENOENT);
    co_return;
  }
  stdx::stop_source stop_source;
  fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
  fuse_entry_param entry = {};
  entry.attr.st_ino = context->next_inode++;
  entry.attr.st_mode = mode;
  entry.attr_timeout = kMetadataTimeout;
  entry.entry_timeout = kMetadataTimeout;
  entry.generation = 1;
  entry.ino = entry.attr.st_ino;
  std::unique_ptr<FuseFileContext> file_context(
      new FuseFileContext{.parent = parent, .flags = fi->flags, .name = name});
  context->file_context.emplace(entry.ino,
                                FuseFileContext{.parent = file_context->parent,
                                                .flags = file_context->flags});
  fi->fh = reinterpret_cast<uint64_t>(file_context.release());
  if (fuse_reply_create(req, &entry, fi) != 0) {
    delete reinterpret_cast<FuseFileContext*>(fi->fh);
  }
}

Task<> Write(fuse_req_t req, fuse_ino_t ino, const char* buf_cstr, size_t size,
             off_t off, struct fuse_file_info* fi) {
  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  auto it = context->file_context.find(ino);
  if (it == context->file_context.end()) {
    fuse_reply_err(req, ENOENT);
    co_return;
  }
  auto file_context = reinterpret_cast<FuseFileContext*>(fi->fh);
  stdx::stop_source stop_source;
  fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
  std::string buf(buf_cstr, size);
  if (!file_context->context.current_write &&
      !file_context->context.current_streaming_write && file_context->name) {
    auto parent_it = context->file_context.find(file_context->parent);
    if (parent_it == context->file_context.end()) {
      fuse_reply_err(req, ENOENT);
      co_return;
    }
    file_context->context = co_await context->context.Create(
        parent_it->second.context, *file_context->name, file_context->size,
        stop_source.get_token());
  }
  co_await context->context.Write(file_context->context, buf, off,
                                  stop_source.get_token());
  fuse_reply_write(req, size);
}

Task<> Unlink(fuse_req_t req, fuse_ino_t parent, const char* name_c_str) {
  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  auto it = context->file_context.find(parent);
  if (it == context->file_context.end()) {
    fuse_reply_err(req, ENOENT);
    co_return;
  }
  stdx::stop_source stop_source;
  fuse_req_interrupt_func(req, InterruptRequest, &stop_source);

  std::string name = name_c_str;
  auto item =
      co_await FindFile(context, it->second, name, stop_source.get_token());
  co_await context->context.Remove(item, stop_source.get_token());
  fuse_reply_err(req, 0);
}

Task<> StatFs(fuse_req_t req, fuse_ino_t ino) {
  if (ino != FUSE_ROOT_ID) {
    fuse_reply_err(req, EINVAL);
    co_return;
  }
  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  stdx::stop_source stop_source;
  fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
  auto volume_data =
      co_await context->context.GetVolumeData(stop_source.get_token());
  if (!volume_data.space_total) {
    fuse_reply_err(req, EIO);
    co_return;
  }
  struct statvfs stat {
    .f_bsize = 1, .f_frsize = 1,
    .f_blocks = static_cast<fsblkcnt_t>(*volume_data.space_total),
    .f_bfree = static_cast<fsblkcnt_t>(*volume_data.space_total -
                                       volume_data.space_used),
    .f_bavail = static_cast<fsblkcnt_t>(*volume_data.space_total -
                                        volume_data.space_used),
    .f_files = std::numeric_limits<fsblkcnt_t>::max(),
    .f_ffree = std::numeric_limits<fsblkcnt_t>::max() - context->next_inode,
    .f_favail = std::numeric_limits<fsblkcnt_t>::max() - context->next_inode,
    .f_fsid = 4444, .f_flag = ST_NOATIME | ST_NODEV | ST_NODIRATIME | ST_NOSUID,
    .f_namemax = std::numeric_limits<fsblkcnt_t>::max()
  };
  fuse_reply_statfs(req, &stat);
}

}  // namespace

int Run(int argc, char** argv) {
  fuse_args args = FUSE_ARGS_INIT(argc, argv);
  auto fuse_args_guard = AtScopeExit([&] { fuse_opt_free_args(&args); });
  std::unique_ptr<fuse_conn_info_opts, FreeDeleter> conn_opts(
      fuse_parse_conn_info_opts(&args));
  fuse_cmdline_opts options;
  if (fuse_parse_cmdline(&args, &options) != 0) {
    return -1;
  }
  auto options_guard = AtScopeExit([&] { free(options.mountpoint); });
  if (options.show_help) {
    fuse_cmdline_help();
    fuse_lib_help(&args);
    return 0;
  }
  if (options.show_version) {
    fuse_lowlevel_version();
    return 0;
  }
  if (!options.mountpoint) {
    std::cerr << "Mountpoint not specified.\n";
    return -1;
  }
  std::unique_ptr<event_base, EventBaseDeleter> event_base([] {
    evthread_use_pthreads();
    return event_base_new();
  }());
  struct CallbackData {
    event fuse_event;
    event signal_event;
    FuseContext* context;
    fuse_session* session;
  } cb_data = {};
  std::unique_ptr<fuse_session, FuseSessionDeleter> session;
  fuse_lowlevel_ops operations = {.init = Init,
                                  .destroy = Destroy,
                                  .lookup = CoroutineT<Lookup>,
                                  .forget = Forget,
                                  .getattr = CoroutineT<GetAttr>,
                                  .setattr = CoroutineT<SetAttr>,
                                  .mkdir = CoroutineT<MkDir>,
                                  .unlink = CoroutineT<Unlink>,
                                  .rmdir = CoroutineT<Unlink>,
                                  .rename = CoroutineT<Rename>,
                                  .open = CoroutineT<Open>,
                                  .read = CoroutineT<Read>,
                                  .write = CoroutineT<Write>,
                                  .release = CoroutineT<Release>,
                                  .opendir = CoroutineT<OpenDir>,
                                  .releasedir = CoroutineT<ReleaseDir>,
                                  .statfs = CoroutineT<StatFs>,
                                  .create = CoroutineT<Create>,
                                  .readdirplus = CoroutineT<ReadDir>};
  try {
    FuseContext context{.context = FileSystemContext(event_base.get()),
                        .conn_opts = conn_opts.get()};
    cb_data.context = &context;
    auto context_guard = AtScopeExit([&] {
      context.context.Quit();
      event_base_dispatch(event_base.get());
    });
    context.file_context.emplace(FUSE_ROOT_ID, FuseFileContext{});
    session =
        std::unique_ptr<fuse_session, FuseSessionDeleter>(fuse_session_new(
            &args, &operations, sizeof(fuse_lowlevel_ops), &context));
    if (!session) {
      throw std::runtime_error("couldn't create fuse_session");
    }
    cb_data.session = session.get();
    Check(fuse_session_mount(session.get(), options.mountpoint));
    auto unmount_guard =
        AtScopeExit([&] { fuse_session_unmount(session.get()); });

    int fd = fuse_session_fd(session.get());
    CheckEvent(event_assign(
        &cb_data.fuse_event, event_base.get(), fd, EV_READ | EV_PERSIST,
        [](evutil_socket_t fd, short, void* d) {
          auto data = reinterpret_cast<CallbackData*>(d);

          fuse_buf buffer = {};
          int size = fuse_session_receive_buf(data->session, &buffer);
          if (size < 0) {
            std::cerr << "FATAL ERROR:" << strerror(-size) << "\n";
            fuse_session_exit(data->session);
          } else {
            fuse_session_process_buf(data->session, &buffer);
            free(buffer.mem);
          }

          if (fuse_session_exited(data->session)) {
            event_del(&data->fuse_event);
            event_del(&data->signal_event);
            data->context->context.Quit();
            return;
          }
        },
        &cb_data));
    CheckEvent(event_add(&cb_data.fuse_event, nullptr));

    CheckEvent(event_assign(
        &cb_data.signal_event, event_base.get(), SIGINT, EV_SIGNAL,
        [](evutil_socket_t fd, short, void* d) {
          auto data = reinterpret_cast<CallbackData*>(d);
          if (!fuse_session_exited(data->session)) {
            fuse_session_exit(data->session);
            event_del(&data->fuse_event);
            event_del(&data->signal_event);
            data->context->context.Quit();
          }
        },
        &cb_data));
    CheckEvent(event_add(&cb_data.signal_event, nullptr));
    if (event_base_dispatch(event_base.get()) != 1) {
      throw std::runtime_error("event_base_dispatch failed");
    }
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "EXCEPTION " << e.what() << "\n";
    return -1;
  }
}

}  // namespace coro::cloudstorage::fuse