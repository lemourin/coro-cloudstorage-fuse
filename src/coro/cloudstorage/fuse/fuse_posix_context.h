#ifndef CORO_CLOUDSTORAGE_FUSE_FUSE_POSIX_CONTEXT_H
#define CORO_CLOUDSTORAGE_FUSE_FUSE_POSIX_CONTEXT_H

#include <coro/promise.h>
#include <coro/task.h>
#include <coro/util/function_traits.h>
#include <fuse_lowlevel.h>

#ifdef CORO_CLOUDSTORAGE_FUSE2
#include <coro/cloudstorage/fuse/fuse_posix_compat.h>
#endif

namespace coro::cloudstorage::fuse {

namespace internal {

inline int ToPosixError(const CloudException& e) {
  switch (e.type()) {
    case CloudException::Type::kNotFound:
      return ENOENT;
    case CloudException::Type::kUnauthorized:
      return EACCES;
    default:
      return EIO;
  }
}

template <auto F, typename, typename>
struct Coroutine;

template <auto F, typename FuseContext, typename... Args>
struct Coroutine<F, FuseContext, coro::util::TypeList<fuse_req_t, Args...>> {
  using type = void (*)(fuse_req_t, Args...);

  static void Do(fuse_req_t req, Args... args) {
    coro::RunTask([req, args...]() -> Task<> {
      auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
      if (context->quitting_) {
        fuse_reply_err(req, ECANCELED);
        co_return;
      }
      context->pending_request_count_++;
      auto scope_guard = coro::util::AtScopeExit([&] {
        context->pending_request_count_--;
        if (context->quitting_ && context->pending_request_count_ == 0) {
          context->no_requests_.SetValue();
        }
      });
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
  };
};

}  // namespace internal

template <typename FileSystemProvider>
class FusePosixContext {
 public:
  static Task<std::unique_ptr<FusePosixContext>> Create(
      event_base* event_base, FileSystemProvider* fs, fuse_args* fuse_args,
      fuse_cmdline_opts* options, fuse_conn_info_opts* conn_opts,
      stdx::stop_token stop_token) {
    co_return std::unique_ptr<FusePosixContext>(new FusePosixContext(
        event_base, fs, fuse_args, options, conn_opts,
        FuseFileContext{.context =
                            co_await fs->GetRoot(std::move(stop_token))}));
  }

  FusePosixContext(const FusePosixContext&) = delete;
  FusePosixContext(FusePosixContext&&) = delete;
  FusePosixContext& operator=(const FusePosixContext&) = delete;
  FusePosixContext& operator=(FusePosixContext&&) = delete;

  void Quit() {
    fuse_session_exit(session_.get());
    quit_.SetValue();
  }

  Task<> Run() {
    co_await quit_;
    quitting_ = true;
    if (pending_request_count_ > 0) {
      co_await no_requests_;
    }
  }

  ~FusePosixContext() {
    for (FuseFileContext* file_context : open_descriptors_) {
      delete file_context;
    }
#ifdef CORO_CLOUDSTORAGE_FUSE2
    fuse_unmount(options_->mountpoint, chan_.get());
    service_thread_.join();
#else
    fuse_session_unmount(session_.get());
    CheckEvent(event_del(&fuse_event_));
#endif
  }

 private:
  using FileContext = typename FileSystemProvider::ItemContextT;
  using FuseContext = FusePosixContext;

  static constexpr int kIndexWidth = sizeof(off_t) * CHAR_BIT / 2;
  static constexpr int kMetadataTimeout = 10;

  struct ReadDirToken {
    off_t page_index;
    off_t offset;
  };

  static ReadDirToken DecodeReadDirToken(off_t d) {
    return ReadDirToken{.page_index = d >> kIndexWidth,
                        .offset = d & ((1ll << kIndexWidth) - 1)};
  }

  static off_t EncodeReadDirToken(ReadDirToken token) {
    return (token.page_index << kIndexWidth) | token.offset;
  }

  struct Flush {
    struct Callback {
      Task<> operator()() const {
        auto& ref = *done;
        co_await ref;
      }
      Promise<void>* done;
    };

    Flush() : promise(Callback{.done = &done}) {}

    int pending_count = 0;
    Promise<void> done;
    SharedPromise<Callback> promise;
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
    bool written_to;
  };

  struct FuseSessionDeleter {
    void operator()(fuse_session* fuse_session) const {
      fuse_session_destroy(fuse_session);
    }
  };

#ifdef CORO_CLOUDSTORAGE_FUSE2
  struct FuseChanDeleter {
    void operator()(fuse_chan* chan) const { fuse_session_remove_chan(chan); }
  };
#endif

  static void Check(int d) {
    if (d != 0) {
      throw std::runtime_error(strerror(d));
    }
  }

  static void CheckEvent(int d) {
    if (d != 0) {
      throw std::runtime_error("libevent error");
    }
  }

#ifdef CORO_CLOUDSTORAGE_FUSE2
  FusePosixContext(event_base* event_base, FileSystemProvider* fs,
                   fuse_args* args, fuse_cmdline_opts* options,
                   fuse_conn_info_opts* conn_opts, FuseFileContext root)
      : file_context_([&] {
          std::unordered_map<fuse_ino_t, FuseFileContext> map;
          map.emplace(FUSE_ROOT_ID, std::move(root));
          return map;
        }()),
        fs_(fs),
        conn_opts_(conn_opts),
        options_(options),
        chan_([&] {
          auto* chan = fuse_mount(options->mountpoint, args);
          if (!chan) {
            throw std::runtime_error("fuse_mount failed");
          }
          return chan;
        }()),
        session_([&] {
          auto* session = fuse_lowlevel_new(args, &operations_,
                                            sizeof(fuse_lowlevel_ops), this);
          if (!session) {
            throw std::runtime_error("couldn't create fuse_session");
          }
          fuse_session_add_chan(session, chan_.get());
          return session;
        }()),
        service_thread_([&, event_loop = coro::util::EventLoop(event_base)] {
          size_t bufsize = fuse_chan_bufsize(chan_.get());
          std::unique_ptr<char[]> chunk(new char[bufsize]);
          while (!fuse_session_exited(session_.get())) {
            fuse_buf buffer = {.size = bufsize, .mem = chunk.get()};
            auto* chan = chan_.release();
            int size = fuse_session_receive_buf(session_.get(), &buffer, &chan);
            chan_.reset(chan);
            if (size < 0) {
              std::cerr << "FATAL ERROR:" << strerror(-size) << "\n";
              fuse_session_exit(session_.get());
            } else {
              event_loop.Do([&] {
                fuse_session_process_buf(session_.get(), &buffer, chan_.get());
              });
            }
            if (fuse_session_exited(session_.get())) {
              event_loop.Do([&] { quit_.SetValue(); });
              return;
            }
          }
        }) {}
#else
  FusePosixContext(event_base* event_base, FileSystemProvider* fs,
                   fuse_args* args, fuse_cmdline_opts* options,
                   fuse_conn_info_opts* conn_opts, FuseFileContext root)
      : fs_(fs),
        conn_opts_(conn_opts),
        session_(fuse_session_new(args, &operations_, sizeof(fuse_lowlevel_ops),
                                  this)) {
    file_context_.emplace(FUSE_ROOT_ID, std::move(root));
    Check(fuse_session_mount(session_.get(), options->mountpoint));
    CheckEvent(event_assign(&fuse_event_, event_base,
                            fuse_session_fd(session_.get()),
                            EV_READ | EV_PERSIST, HandleEvent, this));
    CheckEvent(event_add(&fuse_event_, nullptr));
  }

  static void HandleEvent(evutil_socket_t fd, short, void* d) {
    auto data = reinterpret_cast<FuseContext*>(d);

    fuse_buf buffer = {};
    int size = fuse_session_receive_buf(data->session_.get(), &buffer);
    if (size < 0) {
      std::cerr << "FATAL ERROR:" << strerror(-size) << "\n";
      fuse_session_exit(data->session_.get());
    } else {
      fuse_session_process_buf(data->session_.get(), &buffer);
      free(buffer.mem);
    }

    if (fuse_session_exited(data->session_.get())) {
      data->quit_.SetValue();
      return;
    }
  }
#endif

  static fuse_ino_t CreateNode(FuseContext* context, fuse_ino_t parent,
                               FileContext file_context) {
    auto item_id = file_context.GetId();
    if (auto it = context->inode_.find(item_id);
        it != std::end(context->inode_)) {
      context->file_context_[it->second].context = std::move(file_context);
      return it->second;
    } else {
      context->inode_.emplace(item_id, context->next_inode_);
      context->file_context_[context->next_inode_] =
          FuseFileContext{.context = std::move(file_context), .parent = parent};
      return context->next_inode_++;
    }
  }

  static Task<FileContext> FindFile(FuseContext* context,
                                    const FuseFileContext& parent,
                                    std::string_view name,
                                    stdx::stop_token stop_token) {
    if (parent.flush) {
      co_await parent.flush->promise.Get(stop_token);
    }
    FOR_CO_AWAIT(
        std::vector<FileContext> & page,
        context->fs_->ReadDirectory(parent.context, std::move(stop_token))) {
      for (FileContext& file_context : page) {
        if (name == file_context.GetName()) {
          co_return std::move(file_context);
        }
      }
    }
    throw CloudException(CloudException::Type::kNotFound);
  }

  static struct stat ToStat(const FileContext& item, fuse_ino_t ino) {
    struct stat stat = {};
    stat.st_mode =
        (item.GetType() == FileContext::ItemType::kDirectory ? S_IFDIR
                                                             : S_IFREG) |
        0644;
    stat.st_size = item.GetSize().value_or(0);
#ifndef __APPLE__
    stat.st_mtim.tv_sec = item.GetTimestamp().value_or(0);
#endif
    stat.st_ino = ino;
    return stat;
  }

  static fuse_entry_param CreateFuseEntry(FuseContext* context,
                                          fuse_ino_t parent,
                                          FileContext entry) {
    fuse_entry_param fuse_entry = {};
    auto ino = CreateNode(context, parent, std::move(entry));
    fuse_entry.attr = ToStat(context->file_context_[ino].context, ino);
    context->file_context_[fuse_entry.attr.st_ino].refcount++;
    fuse_entry.attr_timeout = kMetadataTimeout;
    fuse_entry.entry_timeout = kMetadataTimeout;
    fuse_entry.generation = 1;
    fuse_entry.ino = fuse_entry.attr.st_ino;
    return fuse_entry;
  }

  static void InterruptRequest(fuse_req_t, void* user_data) {
    reinterpret_cast<stdx::stop_source*>(user_data)->request_stop();
  }

  static void Init(void* user_data, struct fuse_conn_info* conn) {
#ifndef CORO_CLOUDSTORAGE_FUSE2
    auto context = reinterpret_cast<FuseContext*>(user_data);
    fuse_apply_conn_info_opts(context->conn_opts_, conn);
#endif
  }

  static void Destroy(void* user_data) {}

  static Task<> GetAttr(fuse_req_t req, fuse_ino_t ino, fuse_file_info*) {
    auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
    auto it = context->file_context_.find(ino);
    if (it == context->file_context_.end()) {
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
    if (ino == FUSE_ROOT_ID || !it->second.context.IsPending()) {
      stat = ToStat(it->second.context, ino);
    } else {
      stat.st_mode = S_IFREG | 0644;
      stat.st_ino = ino;
    }
    if (it->second.size) {
      stat.st_size = *it->second.size;
    }
    fuse_reply_attr(req, &stat, kMetadataTimeout);
  }

  static Task<> SetAttr(fuse_req_t req, fuse_ino_t ino, struct stat* attr,
                        int to_set, fuse_file_info* fi) {
    if ((to_set & ~FUSE_SET_ATTR_SIZE) != 0) {
      fuse_reply_err(req, EINVAL);
      co_return;
    }
    auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
    auto it = context->file_context_.find(ino);
    if (it == context->file_context_.end()) {
      fuse_reply_err(req, ENOENT);
      co_return;
    }
    struct stat stat = {};
    if (!it->second.context.IsPending()) {
      stat = ToStat(it->second.context, ino);
    } else {
      stat.st_mode = S_IFREG | 0644;
      stat.st_ino = ino;
    }
    if (it->second.size) {
      stat.st_size = *it->second.size;
    }
    if (to_set & FUSE_SET_ATTR_SIZE) {
      auto file_context = reinterpret_cast<FuseFileContext*>(fi->fh);
      if (attr->st_size == 0 && !it->second.context.IsPending()) {
        auto parent_it = context->file_context_.find(it->second.parent);
        if (parent_it == context->file_context_.end()) {
          fuse_reply_err(req, ENOENT);
          co_return;
        }
        stdx::stop_source stop_source;
        fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
        it->second.context = co_await context->fs_->Flush(
            co_await context->fs_->Create(parent_it->second.context,
                                          it->second.context.GetName(),
                                          /*size=*/0, stop_source.get_token()),
            stop_source.get_token());
        if (file_context) {
          file_context->context = FileContext::From(it->second.context);
        }
      } else if (!it->second.context.IsPending()) {
        fuse_reply_err(req, EINVAL);
        co_return;
      }
      it->second.size = attr->st_size;
      if (file_context) {
        file_context->size = attr->st_size;
      }
    }
    fuse_reply_attr(req, &stat, kMetadataTimeout);
  }

  static Task<> Open(fuse_req_t req, fuse_ino_t ino,
                     struct fuse_file_info* fi) {
    auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
    auto it = context->file_context_.find(ino);
    if (it == context->file_context_.end()) {
      fuse_reply_err(req, ENOENT);
      co_return;
    }
    if (it->second.flush) {
      stdx::stop_source stop_source;
      fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
      const auto& promise = it->second.flush->promise;
      co_await promise.Get(stop_source.get_token());
    }
    std::unique_ptr<FuseFileContext> file_context(
        new FuseFileContext{.context = FileContext::From(it->second.context),
                            .parent = it->second.parent,
                            .flags = fi->flags});
    fi->fh = reinterpret_cast<uint64_t>(file_context.get());
    if (fuse_reply_open(req, fi) == 0) {
      context->open_descriptors_.insert(file_context.release());
    }
  }

  static Task<> OpenDir(fuse_req_t req, fuse_ino_t ino, fuse_file_info* fi) {
    return Open(req, ino, fi);
  }

  static Task<> Release(fuse_req_t req, fuse_ino_t ino, fuse_file_info* fi) {
    std::unique_ptr<FuseFileContext> file_context(
        reinterpret_cast<FuseFileContext*>(fi->fh));
    auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
    context->open_descriptors_.erase(file_context.get());
    if (!(file_context->flags & (O_RDWR | O_WRONLY))) {
      fuse_reply_err(req, 0);
      co_return;
    }
    stdx::stop_source stop_source;
    fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
    if (!file_context->written_to && file_context->name) {
      auto parent_it = context->file_context_.find(file_context->parent);
      if (parent_it == context->file_context_.end()) {
        fuse_reply_err(req, ENOENT);
        co_return;
      }
      file_context->context = co_await context->fs_->Create(
          parent_it->second.context, *file_context->name, 0,
          stop_source.get_token());
    }
    if (file_context->written_to) {
      auto it = context->file_context_.find(ino);
      if (it == std::end(context->file_context_)) {
        fuse_reply_err(req, ENOENT);
        co_return;
      }
      auto parent_it = context->file_context_.find(file_context->parent);
      auto guard = coro::util::AtScopeExit([&] {
        if (parent_it != std::end(context->file_context_)) {
          parent_it->second.flush->pending_count--;
          if (parent_it->second.flush->pending_count == 0) {
            parent_it->second.flush->done.SetValue();
            parent_it->second.flush = nullptr;
          }
        }
      });
      if (parent_it != std::end(context->file_context_)) {
        if (!parent_it->second.flush) {
          parent_it->second.flush = std::make_unique<Flush>();
        }
        parent_it->second.flush->pending_count++;
      }
      it->second.flush = std::make_unique<Flush>();
      try {
        auto new_item = co_await context->fs_->Flush(file_context->context,
                                                     stop_source.get_token());
        auto new_id = new_item.GetId();
        context->inode_.emplace(new_id, ino);
        it->second.context = std::move(new_item);
        it->second.flush->done.SetValue();
      } catch (...) {
        it->second.flush->done.SetException(std::current_exception());
      }
    }
    fuse_reply_err(req, 0);
  }

  static Task<> ReleaseDir(fuse_req_t req, fuse_ino_t ino, fuse_file_info* fi) {
    return Release(req, ino, fi);
  }

  static Task<> ReadDir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                        fuse_file_info* fi) {
    auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
    auto it = context->file_context_.find(ino);
    if (it == context->file_context_.end()) {
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
    auto page = co_await context->fs_->ReadDirectoryPage(
        file_context.context,
        read_dir_token.page_index == 0
            ? std::nullopt
            : std::make_optional(
                  file_context.page_token[read_dir_token.page_index]),
        stop_source.get_token());
    for (int i = read_dir_token.offset; i < page.items.size(); i++) {
      FileContext& entry = page.items[i];
      std::string name(entry.GetName());
      fuse_entry_param fuse_entry = {};
      auto new_node = CreateNode(context, ino, std::move(entry));
      fuse_entry.attr =
          ToStat(context->file_context_[new_node].context, new_node);
      fuse_entry.generation = 1;
      fuse_entry.ino = fuse_entry.attr.st_ino;
      fuse_entry.attr_timeout = kMetadataTimeout;
      fuse_entry.entry_timeout = kMetadataTimeout;
#ifdef CORO_CLOUDSTORAGE_FUSE2
      auto entry_size =
          fuse_add_direntry(req, nullptr, 0, name.c_str(), nullptr, 0);
#else
      auto entry_size =
          fuse_add_direntry_plus(req, nullptr, 0, name.c_str(), nullptr, 0);
#endif
      if (offset + entry_size < size) {
        context->file_context_[fuse_entry.ino].refcount++;
        ReadDirToken next_token;
        if (i + 1 == page.items.size()) {
          next_token = {.page_index = read_dir_token.page_index + 1,
                        .offset = 0};
          if (read_dir_token.page_index + 1 >= file_context.page_token.size()) {
            file_context.page_token.emplace_back(
                page.next_page_token.value_or(""));
          }
        } else {
          next_token = {.page_index = read_dir_token.page_index,
                        .offset = i + 1};
        }
#ifdef CORO_CLOUDSTORAGE_FUSE2
        offset += fuse_add_direntry(req, buffer.data() + offset, size - offset,
                                    name.c_str(), &fuse_entry.attr,
                                    EncodeReadDirToken(next_token));
#else
        offset += fuse_add_direntry_plus(
            req, buffer.data() + offset, size - offset, name.c_str(),
            &fuse_entry, EncodeReadDirToken(next_token));
#endif
      } else {
        break;
      }
      current_index++;
    }
    fuse_reply_buf(req, buffer.data(), offset);
  }

  static Task<> Lookup(fuse_req_t req, fuse_ino_t parent,
                       const char* name_c_str) {
    auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
    auto it = context->file_context_.find(parent);
    if (it == context->file_context_.end()) {
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

#ifdef CORO_CLOUDSTORAGE_FUSE2
  using nlookup_t = unsigned long;
#else
  using nlookup_t = uint64_t;
#endif
  static void Forget(fuse_req_t req, fuse_ino_t ino, nlookup_t nlookup) {
    auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
    auto it = context->file_context_.find(ino);
    if (it == context->file_context_.end()) {
      fuse_reply_none(req);
      return;
    }
    it->second.refcount -= nlookup;
    if (it->second.refcount == 0) {
      context->inode_.erase(it->second.context.GetId());
      context->file_context_.erase(it);
    }
    fuse_reply_none(req);
  }

  static Task<> Read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                     struct fuse_file_info* fi) {
    auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
    auto it = context->file_context_.find(ino);
    if (it == context->file_context_.end()) {
      fuse_reply_err(req, ENOENT);
      co_return;
    }
    auto file_context = reinterpret_cast<FuseFileContext*>(fi->fh);
    stdx::stop_source stop_source;
    fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
    auto data = co_await context->fs_->Read(file_context->context, off, size,
                                            stop_source.get_token());
    fuse_reply_buf(req, data.data(), data.size());
  }

  static Task<> Rename2(fuse_req_t req, fuse_ino_t parent,
                        const char* name_c_str, fuse_ino_t new_parent,
                        const char* new_name_c_str) {
    return Rename3(req, parent, name_c_str, new_parent, new_name_c_str, 0);
  }

  static Task<> Rename3(fuse_req_t req, fuse_ino_t parent,
                        const char* name_c_str, fuse_ino_t new_parent,
                        const char* new_name_c_str, unsigned int flags) {
    auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
    auto it_parent = context->file_context_.find(parent);
    if (it_parent == context->file_context_.end()) {
      fuse_reply_err(req, ENOENT);
      co_return;
    }

    std::string name = name_c_str;
    std::string new_name = new_name_c_str;
    stdx::stop_source stop_source;
    fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
    auto source_item = co_await FindFile(context, it_parent->second, name,
                                         stop_source.get_token());
    auto previous_id = source_item.GetId();

    FileContext new_item = FileContext::From(source_item);
    if (name != new_name) {
      new_item = co_await context->fs_->Rename(source_item, new_name,
                                               stop_source.get_token());
    }

    if (parent != new_parent) {
      auto it_new_parent = context->file_context_.find(new_parent);
      if (it_new_parent == context->file_context_.end()) {
        fuse_reply_err(req, ENOENT);
        co_return;
      }
      new_item = co_await context->fs_->Move(
          new_item, it_new_parent->second.context, stop_source.get_token());
    }

    if (auto it = context->inode_.find(previous_id);
        it != std::end(context->inode_)) {
      auto inode = it->second;
      auto new_id = new_item.GetId();
      context->inode_.erase(it);
      context->inode_.emplace(new_id, inode);
      auto& file_context = context->file_context_[inode];
      file_context.context = std::move(new_item);
      file_context.parent = parent;
    }
    fuse_reply_err(req, 0);
  }

  static Task<> MkDir(fuse_req_t req, fuse_ino_t parent, const char* name,
                      mode_t mode) {
    auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
    auto it = context->file_context_.find(parent);
    if (it == context->file_context_.end()) {
      fuse_reply_err(req, ENOENT);
      co_return;
    }

    stdx::stop_source stop_source;
    fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
    auto new_directory = co_await context->fs_->CreateDirectory(
        it->second.context, std::string(name), stop_source.get_token());

    fuse_entry_param entry =
        CreateFuseEntry(context, parent, std::move(new_directory));
    fuse_reply_entry(req, &entry);
  }

  static Task<> CreateFile(fuse_req_t req, fuse_ino_t parent, const char* name,
                           mode_t mode, struct fuse_file_info* fi) {
    auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
    auto parent_it = context->file_context_.find(parent);
    if (parent_it == context->file_context_.end()) {
      fuse_reply_err(req, ENOENT);
      co_return;
    }
    stdx::stop_source stop_source;
    fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
    fuse_entry_param entry = {};
    entry.attr.st_ino = context->next_inode_++;
    entry.attr.st_mode = mode;
    entry.attr_timeout = kMetadataTimeout;
    entry.entry_timeout = kMetadataTimeout;
    entry.generation = 1;
    entry.ino = entry.attr.st_ino;
    std::unique_ptr<FuseFileContext> file_context(new FuseFileContext{
        .parent = parent, .flags = fi->flags, .name = name});
    context->file_context_.emplace(
        entry.ino, FuseFileContext{.parent = file_context->parent,
                                   .flags = file_context->flags,
                                   .name = name});
    fi->fh = reinterpret_cast<uint64_t>(file_context.get());
    if (fuse_reply_create(req, &entry, fi) == 0) {
      context->open_descriptors_.insert(file_context.release());
    }
  }

  static Task<> Write(fuse_req_t req, fuse_ino_t ino, const char* buf_cstr,
                      size_t size, off_t off, struct fuse_file_info* fi) {
    auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
    auto it = context->file_context_.find(ino);
    if (it == context->file_context_.end()) {
      fuse_reply_err(req, ENOENT);
      co_return;
    }
    auto file_context = reinterpret_cast<FuseFileContext*>(fi->fh);
    stdx::stop_source stop_source;
    fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
    std::string buf(buf_cstr, size);
    if (!file_context->written_to && file_context->name) {
      auto parent_it = context->file_context_.find(file_context->parent);
      if (parent_it == context->file_context_.end()) {
        fuse_reply_err(req, ENOENT);
        co_return;
      }
      file_context->context = co_await context->fs_->Create(
          parent_it->second.context, *file_context->name, file_context->size,
          stop_source.get_token());
    }
    co_await context->fs_->Write(file_context->context, buf, off,
                                 stop_source.get_token());
    file_context->written_to = true;
    it->second.size =
        std::max<int64_t>(it->second.size.value_or(0), off + size);
    fuse_reply_write(req, size);
  }

  static Task<> Unlink(fuse_req_t req, fuse_ino_t parent,
                       const char* name_c_str) {
    auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
    auto it = context->file_context_.find(parent);
    if (it == context->file_context_.end()) {
      fuse_reply_err(req, ENOENT);
      co_return;
    }
    stdx::stop_source stop_source;
    fuse_req_interrupt_func(req, InterruptRequest, &stop_source);

    std::string name = name_c_str;
    auto item =
        co_await FindFile(context, it->second, name, stop_source.get_token());
    co_await context->fs_->Remove(item, stop_source.get_token());
    fuse_reply_err(req, 0);
  }

  static Task<> StatFs(fuse_req_t req, fuse_ino_t ino) {
    if (ino != FUSE_ROOT_ID) {
      fuse_reply_err(req, EINVAL);
      co_return;
    }
    auto context = reinterpret_cast<FuseContext*>(fuse_req_userdata(req));
    stdx::stop_source stop_source;
    fuse_req_interrupt_func(req, InterruptRequest, &stop_source);
    auto volume_data =
        co_await context->fs_->GetVolumeData(stop_source.get_token());
    if (!volume_data.space_total || !volume_data.space_used) {
      fuse_reply_err(req, EIO);
      co_return;
    }
    struct statvfs stat {
      .f_bsize = 1, .f_frsize = 1,
      .f_blocks = static_cast<fsblkcnt_t>(*volume_data.space_total),
      .f_bfree = static_cast<fsblkcnt_t>(*volume_data.space_total -
                                         *volume_data.space_used),
      .f_bavail = static_cast<fsblkcnt_t>(*volume_data.space_total -
                                          *volume_data.space_used),
      .f_files = std::numeric_limits<fsblkcnt_t>::max(),
      .f_ffree = std::numeric_limits<fsblkcnt_t>::max() - context->next_inode_,
      .f_favail = std::numeric_limits<fsblkcnt_t>::max() - context->next_inode_,
      .f_fsid = 4444, .f_flag = 0,
      .f_namemax = std::numeric_limits<unsigned long>::max()
    };
#ifdef ST_NOATIME
    stat.f_flag |= ST_NOATIME;
#endif
#ifdef ST_NODEV
    stat.f_flag |= ST_NODEV;
#endif
#ifdef ST_NODIRATIME
    stat.f_flag |= ST_NODIRATIME;
#endif
#ifdef ST_NOSUID
    stat.f_flag |= ST_NOSUID;
#endif
    fuse_reply_statfs(req, &stat);
  }

  template <auto F>
  using Coroutine =
      internal::Coroutine<F, FusePosixContext,
                          coro::util::ArgumentListTypeT<decltype(F)>>;

  template <auto F>
  static constexpr typename Coroutine<F>::type CoroutineT = Coroutine<F>::Do;

  template <auto F, typename, typename>
  friend class internal::Coroutine;

  std::unordered_map<fuse_ino_t, FuseFileContext> file_context_;
  std::unordered_map<std::string, fuse_ino_t> inode_;
  FileSystemProvider* fs_;
  int next_inode_ = FUSE_ROOT_ID + 1;
  fuse_conn_info_opts* conn_opts_;
  std::unordered_set<FuseFileContext*> open_descriptors_;
  int pending_request_count_ = 0;
  bool quitting_ = false;
  Promise<void> quit_;
  Promise<void> no_requests_;
  fuse_lowlevel_ops operations_ = {.init = Init,
                                   .destroy = Destroy,
                                   .lookup = CoroutineT<Lookup>,
                                   .forget = Forget,
                                   .getattr = CoroutineT<GetAttr>,
                                   .setattr = CoroutineT<SetAttr>,
                                   .mkdir = CoroutineT<MkDir>,
                                   .unlink = CoroutineT<Unlink>,
                                   .rmdir = CoroutineT<Unlink>,
#ifdef CORO_CLOUDSTORAGE_FUSE2
                                   .rename = CoroutineT<Rename2>,
#else
                                   .rename = CoroutineT<Rename3>,
#endif
                                   .open = CoroutineT<Open>,
                                   .read = CoroutineT<Read>,
                                   .write = CoroutineT<Write>,
                                   .release = CoroutineT<Release>,
                                   .opendir = CoroutineT<OpenDir>,
#ifdef CORO_CLOUDSTORAGE_FUSE2
                                   .readdir = CoroutineT<ReadDir>,
#endif
                                   .releasedir = CoroutineT<ReleaseDir>,
                                   .statfs = CoroutineT<StatFs>,
                                   .create = CoroutineT<CreateFile>,
#ifndef CORO_CLOUDSTORAGE_FUSE2
                                   .readdirplus = CoroutineT<ReadDir>
#endif
  };
#ifdef CORO_CLOUDSTORAGE_FUSE2
  fuse_cmdline_opts* options_;
  std::unique_ptr<fuse_chan, FuseChanDeleter> chan_;
#endif
  std::unique_ptr<fuse_session, FuseSessionDeleter> session_;
#ifdef CORO_CLOUDSTORAGE_FUSE2
  std::thread service_thread_;
#else
  event fuse_event_;
#endif
};

}  // namespace coro::cloudstorage::fuse

#endif  // CORO_CLOUDSTORAGE_FUSE_FUSE_POSIX_CONTEXT_H
