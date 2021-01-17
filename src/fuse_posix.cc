#include "fuse_posix.h"

#define FUSE_USE_VERSION 39
#include <coro/util/function_traits.h>
#include <fuse.h>
#include <fuse_lowlevel.h>

#include <cfloat>
#include <csignal>
#include <iostream>

#include "filesystem_context.h"

namespace coro::cloudstorage::fuse {

namespace {

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

struct FuseFileContext {
  FileContext context;
  int64_t refcount;
  std::vector<std::string> page_token = {""};
};

struct FuseContext {
  std::unordered_map<int64_t, FuseFileContext> file_context;
  std::unordered_map<std::string, int64_t> inode;
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

template <typename T>
auto AtScopeExit(T func) {
  struct Guard {
    Guard(T func) : func(std::move(func)) {}
    ~Guard() { func(); }
    T func;
  };
  return Guard(std::move(func));
}

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

fuse_ino_t CreateNode(FuseContext* context, FileContext file_context) {
  auto generic_item = FileSystemContext::GetGenericItem(file_context);
  auto item_id =
      std::visit(
          [](const auto& item) {
            return std::to_string(reinterpret_cast<intptr_t>(item.provider()));
          },
          *file_context.item) +
      '#' + generic_item.id;
  if (auto it = context->inode.find(item_id); it != std::end(context->inode)) {
    return it->second;
  } else {
    context->inode.emplace(item_id, context->next_inode);
    context->file_context.emplace(
        context->next_inode,
        FuseFileContext{.context = std::move(file_context)});
    return context->next_inode++;
  }
}

Task<FileContext> FindFile(FuseContext* context, const FileContext& parent,
                           std::string_view name, stdx::stop_token stop_token) {
  FOR_CO_AWAIT(std::vector<FileContext> & page,
               context->context.ReadDirectory(parent, std::move(stop_token))) {
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
  stat.st_mode = (item.is_directory ? S_IFDIR : S_IFREG) | 0644;
  stat.st_size = item.size.value_or(0);
  stat.st_mtim.tv_sec = item.timestamp.value_or(0);
  return stat;
}

fuse_entry_param CreateFuseEntry(FuseContext* context, FileContext entry) {
  auto item = FileSystemContext::GetGenericItem(entry);
  fuse_entry_param fuse_entry = {};
  fuse_entry.attr = ToStat(item);
  fuse_entry.attr.st_ino = CreateNode(context, std::move(entry));
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

void GetAttr(fuse_req_t req, fuse_ino_t ino, fuse_file_info*) {
  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  auto it = context->file_context.find(ino);
  if (it == context->file_context.end()) {
    fuse_reply_err(req, ENOENT);
    return;
  }
  struct stat stat =
      ToStat(FileSystemContext::GetGenericItem(it->second.context));
  stat.st_ino = ino;
  fuse_reply_attr(req, &stat, kMetadataTimeout);
}

void Open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi) {
  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  auto it = context->file_context.find(ino);
  if (it == context->file_context.end()) {
    fuse_reply_err(req, ENOENT);
    return;
  }
  fi->fh = reinterpret_cast<uint64_t>(new FuseFileContext{
      .context = FileContext{.item = it->second.context.item}});
  if (fuse_reply_open(req, fi) != 0) {
    delete reinterpret_cast<FuseFileContext*>(fi->fh);
  }
}

void OpenDir(fuse_req_t req, fuse_ino_t ino, fuse_file_info* fi) {
  Open(req, ino, fi);
}

void Release(fuse_req_t req, fuse_ino_t ino, fuse_file_info* fi) {
  delete reinterpret_cast<FuseFileContext*>(fi->fh);
  fuse_reply_err(req, 0);
}

void ReleaseDir(fuse_req_t req, fuse_ino_t ino, fuse_file_info* fi) {
  Release(req, ino, fi);
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
    fuse_entry.attr.st_ino = CreateNode(context, std::move(entry));
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
  auto entry = co_await FindFile(context, file_context.context, name,
                                 stop_source.get_token());
  fuse_entry_param fuse_entry = CreateFuseEntry(context, std::move(entry));
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
    context->inode.erase(
        FileSystemContext::GetGenericItem(it->second.context).id);
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
  auto item = FileSystemContext::GetGenericItem(file_context->context);
  stdx::stop_source stop_source;
  fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
  auto data = co_await context->context.Read(file_context->context, off, size,
                                             stop_source.get_token());
  fuse_reply_buf(req, data.data(), data.size());
}

Task<> Rename(fuse_req_t req, fuse_ino_t parent, const char* name_c_str,
              fuse_ino_t new_parent, const char* new_name_c_str,
              unsigned int flags) {
  if (parent != new_parent) {
    fuse_reply_err(req, EIO);
    co_return;
  }

  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  auto it_parent = context->file_context.find(parent);
  if (it_parent == context->file_context.end()) {
    fuse_reply_err(req, ENOENT);
    co_return;
  }
  auto it_new_parent = context->file_context.find(new_parent);
  if (it_new_parent == context->file_context.end()) {
    fuse_reply_err(req, ENOENT);
    co_return;
  }

  std::string name = name_c_str;
  std::string new_name = new_name_c_str;
  stdx::stop_source stop_source;
  fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
  auto item = co_await FindFile(context, it_parent->second.context, name,
                                stop_source.get_token());
  std::string previous_id = FileSystemContext::GetGenericItem(item).id;
  auto new_item =
      co_await context->context.Rename(item, new_name, stop_source.get_token());
  if (auto it = context->inode.find(previous_id);
      it != std::end(context->inode)) {
    auto inode = it->second;
    context->file_context.erase(it->second);
    context->inode.erase(it);
    context->inode.emplace(FileSystemContext::GetGenericItem(new_item).id,
                           inode);
    context->file_context.emplace(
        inode, FuseFileContext{.context = std::move(new_item)});
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

  fuse_entry_param entry = CreateFuseEntry(context, std::move(new_directory));
  fuse_reply_entry(req, &entry);
  co_return;
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
  auto item = co_await FindFile(context, it->second.context, name,
                                stop_source.get_token());
  co_await context->context.Remove(item, stop_source.get_token());
  fuse_reply_err(req, 0);
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
  std::unique_ptr<event_base, EventBaseDeleter> event_base(event_base_new());
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
                                  .getattr = GetAttr,
                                  .mkdir = CoroutineT<MkDir>,
                                  .unlink = CoroutineT<Unlink>,
                                  .rmdir = CoroutineT<Unlink>,
                                  .rename = CoroutineT<Rename>,
                                  .open = Open,
                                  .read = CoroutineT<Read>,
                                  .release = Release,
                                  .opendir = OpenDir,
                                  .releasedir = ReleaseDir,
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