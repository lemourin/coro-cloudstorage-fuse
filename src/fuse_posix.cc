#include "fuse_posix.h"

#define FUSE_USE_VERSION 39
#include <fuse_lowlevel.h>

#include <cfloat>
#include <csignal>
#include <iostream>

#include "filesystem_context.h"

namespace coro::cloudstorage::fuse {

namespace {

using FileContext = FileSystemContext::FileContext;

struct FuseFileContext {
  FileContext context;
  std::optional<std::unordered_map<std::string, int64_t>> children;
  int64_t refcount;
};

struct FuseContext {
  std::unordered_map<int64_t, FuseFileContext> file_context;
  std::unordered_map<std::string, int64_t> inode;
  FileSystemContext context;
  int next_inode = FUSE_ROOT_ID + 1;
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

struct stat ToStat(const FileSystemContext::GenericItem& item) {
  struct stat stat = {};
  stat.st_mode = (item.is_directory ? S_IFDIR : S_IFREG) | 0644;
  stat.st_size = item.size.value_or(0);
  stat.st_mtim.tv_sec = item.timestamp.value_or(0);
  return stat;
}

void InterruptRequest(fuse_req_t, void* user_data) {
  reinterpret_cast<stdx::stop_source*>(user_data)->request_stop();
}

void Init(void* user_data, struct fuse_conn_info* conn) {}

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
  fuse_reply_attr(req, &stat, DBL_MAX);
}

void Open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi) {
  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  auto it = context->file_context.find(ino);
  if (it == context->file_context.end()) {
    fuse_reply_err(req, ENOENT);
    return;
  }
  fi->fh = reinterpret_cast<uint64_t>(
      new FileSystemContext::FileContext{.item = it->second.context.item});
  if (fuse_reply_open(req, fi) != 0) {
    delete reinterpret_cast<FileSystemContext::FileContext*>(fi->fh);
  }
}

void OpenDir(fuse_req_t req, fuse_ino_t ino, fuse_file_info* fi) {
  Open(req, ino, fi);
}

void Release(fuse_req_t req, fuse_ino_t ino, fuse_file_info* fi) {
  delete reinterpret_cast<FileSystemContext::FileContext*>(fi->fh);
  fuse_reply_err(req, 0);
}

void ReleaseDir(fuse_req_t req, fuse_ino_t ino, fuse_file_info* fi) {
  Release(req, ino, fi);
}

void ReadDir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
             fuse_file_info* fi) {
  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  auto it = context->file_context.find(ino);
  if (it == context->file_context.end()) {
    fuse_reply_err(req, ENOENT);
    return;
  }
  coro::Invoke([=]() -> Task<> {
    try {
      std::string buffer(size, 0);
      int offset = 0;
      int current_index = 0;
      std::unordered_map<std::string, int64_t> children;
      auto& file_context = it->second;
      stdx::stop_source stop_source;
      fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
      FOR_CO_AWAIT(std::vector<FileContext> & page,
                   context->context.ReadDirectory(file_context.context,
                                                  stop_source.get_token())) {
        for (FileContext& entry : page) {
          auto generic_item = FileSystemContext::GetGenericItem(entry);
          struct stat stat = ToStat(generic_item);
          if (auto it = context->inode.find(generic_item.id);
              it != std::end(context->inode)) {
            stat.st_ino = it->second;
          } else {
            stat.st_ino = context->next_inode++;
            context->inode.emplace(generic_item.id, stat.st_ino);
            context->file_context.emplace(
                stat.st_ino, FuseFileContext{.context = std::move(entry)});
          }
          children.emplace(generic_item.name, stat.st_ino);
          if (current_index >= off) {
            auto entry_size = fuse_add_direntry(
                req, nullptr, 0, generic_item.name.c_str(), nullptr, 0);
            if (offset + entry_size < size) {
              offset += fuse_add_direntry(
                  req, buffer.data() + offset, size - offset,
                  generic_item.name.c_str(), &stat, current_index + 1);
            }
          }
          current_index++;
        }
      }
      file_context.children = std::move(children);
      fuse_reply_buf(req, buffer.data(), offset);
    } catch (const CloudException& e) {
      fuse_reply_err(req, ToPosixError(e));
    } catch (const InterruptedException&) {
      fuse_reply_err(req, ECANCELED);
    } catch (...) {
      fuse_reply_err(req, EIO);
    }
  });
}

void Lookup(fuse_req_t req, fuse_ino_t parent, const char* name) {
  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  auto it = context->file_context.find(parent);
  if (it == context->file_context.end()) {
    fuse_reply_err(req, ENOENT);
    return;
  }
  coro::Invoke([context, req, it, name = std::string(name)]() -> Task<> {
    try {
      auto& file_context = it->second;
      if (!file_context.children) {
        std::unordered_map<std::string, int64_t> children;
        stdx::stop_source stop_source;
        fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
        FOR_CO_AWAIT(std::vector<FileContext> & page,
                     context->context.ReadDirectory(it->second.context,
                                                    stop_source.get_token())) {
          for (FileContext& entry : page) {
            auto generic_item = FileSystemContext::GetGenericItem(entry);
            int64_t inode;
            if (auto it = context->inode.find(generic_item.id);
                it != std::end(context->inode)) {
              inode = it->second;
            } else {
              inode = context->next_inode++;
              context->inode.emplace(generic_item.id, inode);
              context->file_context.emplace(
                  inode, FuseFileContext{.context = std::move(entry)});
            }
            children.emplace(generic_item.name, inode);
          }
        }
        file_context.children = std::move(children);
      }
      auto entry_it = file_context.children->find(name);
      if (entry_it == file_context.children->end()) {
        fuse_reply_err(req, ENOENT);
        co_return;
      }
      auto file_context_it = context->file_context.find(entry_it->second);
      if (file_context_it == context->file_context.end()) {
        fuse_reply_err(req, ENOENT);
        co_return;
      }
      auto item =
          FileSystemContext::GetGenericItem(file_context_it->second.context);
      fuse_entry_param entry = {};
      entry.attr = ToStat(item);
      entry.attr.st_ino = entry_it->second;
      entry.entry_timeout = 1.0;
      entry.generation = 1;
      entry.ino = entry.attr.st_ino;
      file_context_it->second.refcount++;
      fuse_reply_entry(req, &entry);
    } catch (const CloudException& e) {
      fuse_reply_err(req, ToPosixError(e));
    } catch (const InterruptedException&) {
      fuse_reply_err(req, ECANCELED);
    } catch (...) {
      fuse_reply_err(req, EIO);
    }
  });
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

void Read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
          struct fuse_file_info* fi) {
  auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
  auto it = context->file_context.find(ino);
  if (it == context->file_context.end()) {
    fuse_reply_err(req, ENOENT);
    return;
  }
  auto file_context = reinterpret_cast<FileSystemContext::FileContext*>(fi->fh);
  auto item = FileSystemContext::GetGenericItem(*file_context);
  std::cerr << "TRYING TO READ " << size << " " << off << " " << item.name
            << "\n";
  coro::Invoke([req, context, file_context, off, size]() -> Task<> {
    try {
      stdx::stop_source stop_source;
      fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
      auto data = co_await context->context.Read(*file_context, off, size,
                                                 stop_source.get_token());
      fuse_reply_buf(req, data.data(), data.size());
    } catch (const CloudException& e) {
      fuse_reply_err(req, ToPosixError(e));
    } catch (const InterruptedException&) {
      fuse_reply_err(req, ECANCELED);
    } catch (...) {
      fuse_reply_err(req, EIO);
    }
  });
}

}  // namespace

int Run(int argc, char** argv) {
  std::unique_ptr<event_base, EventBaseDeleter> event_base(event_base_new());
  FuseContext context{.context = FileSystemContext(event_base.get())};
  context.file_context.emplace(FUSE_ROOT_ID, FuseFileContext{});
  fuse_lowlevel_ops operations = {.init = Init,
                                  .destroy = Destroy,
                                  .lookup = Lookup,
                                  .forget = Forget,
                                  .getattr = GetAttr,
                                  .open = Open,
                                  .read = Read,
                                  .release = Release,
                                  .opendir = OpenDir,
                                  .readdir = ReadDir,
                                  .releasedir = ReleaseDir};
  fuse_args args = FUSE_ARGS_INIT(argc, argv);
  auto fuse_args_guard = AtScopeExit([&] { fuse_opt_free_args(&args); });
  std::unique_ptr<fuse_session, FuseSessionDeleter> session(fuse_session_new(
      &args, &operations, sizeof(fuse_lowlevel_ops), &context));
  if (!session) {
    return -1;
  }
  Check(fuse_session_mount(session.get(), "mount"));
  auto unmount_guard =
      AtScopeExit([&] { fuse_session_unmount(session.get()); });

  struct CallbackData {
    event fuse_event;
    event signal_event;
    FuseContext* context;
    fuse_session* session;
  };

  int fd = fuse_session_fd(session.get());
  CallbackData cb_data{.context = &context, .session = session.get()};
  event_assign(
      &cb_data.fuse_event, event_base.get(), fd, EV_READ | EV_PERSIST,
      [](evutil_socket_t fd, short, void* d) {
        auto data = reinterpret_cast<CallbackData*>(d);

        fuse_buf buffer = {};
        int size = fuse_session_receive_buf(data->session, &buffer);
        if (size < 0) {
          throw std::runtime_error(strerror(-size));
        }
        fuse_session_process_buf(data->session, &buffer);
        free(buffer.mem);

        if (fuse_session_exited(data->session)) {
          event_del(&data->fuse_event);
          event_del(&data->signal_event);
          data->context->context.Quit();
          return;
        }
      },
      &cb_data);
  event_add(&cb_data.fuse_event, nullptr);

  event_assign(
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
      &cb_data);
  event_add(&cb_data.signal_event, nullptr);

  event_base_dispatch(event_base.get());
  return 0;
}

}  // namespace coro::cloudstorage::fuse