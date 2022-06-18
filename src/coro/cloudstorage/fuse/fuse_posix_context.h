#ifndef CORO_CLOUDSTORAGE_FUSE_FUSE_POSIX_CONTEXT_H
#define CORO_CLOUDSTORAGE_FUSE_FUSE_POSIX_CONTEXT_H

#include <event2/event.h>
#include <event2/event_struct.h>
#include <fuse_lowlevel.h>

#include "coro/cloudstorage/cloud_exception.h"
#include "coro/cloudstorage/fuse/filesystem_provider.h"
#include "coro/cloudstorage/fuse/fuse_posix_compat.h"
#include "coro/cloudstorage/fuse/item_context.h"
#include "coro/cloudstorage/util/string_utils.h"
#include "coro/promise.h"
#include "coro/stdx/stop_token.h"
#include "coro/task.h"
#include "coro/util/event_loop.h"
#include "coro/util/function_traits.h"
#include "coro/util/raii_utils.h"

namespace coro::cloudstorage::fuse {

class FusePosixContext {
 public:
  static Task<std::unique_ptr<FusePosixContext>> Create(
      const coro::util::EventLoop* event_loop, FileSystemProvider* fs,
      fuse_args* fuse_args, fuse_cmdline_opts* options,
      fuse_conn_info_opts* conn_opts, stdx::stop_token stop_token);

  FusePosixContext(const FusePosixContext&) = delete;
  FusePosixContext(FusePosixContext&&) = delete;
  FusePosixContext& operator=(const FusePosixContext&) = delete;
  FusePosixContext& operator=(FusePosixContext&&) = delete;

  ~FusePosixContext();

  void Quit();

  Task<> Run();

 private:
  using FileContext = ItemContext;
  using FuseContext = FusePosixContext;

  struct Flush {
    struct Callback {
      Task<> operator()() const { co_await *done; }
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

  FusePosixContext(const coro::util::EventLoop* event_loop,
                   FileSystemProvider* fs, fuse_args* args,
                   fuse_cmdline_opts* options, fuse_conn_info_opts* conn_opts,
                   FuseFileContext root);

  static fuse_lowlevel_ops GetFuseLowLevelOps();

#ifndef CORO_CLOUDSTORAGE_FUSE2
  static void HandleEvent(evutil_socket_t fd, short, void* d);
#endif

  static fuse_ino_t CreateNode(FuseContext* context, fuse_ino_t parent,
                               FileContext file_context);

  static Task<FileContext> FindFile(FuseContext* context,
                                    const FuseFileContext& parent,
                                    std::string_view name,
                                    stdx::stop_token stop_token);

  static struct stat ToStat(const FileContext& item, fuse_ino_t ino);

  static fuse_entry_param CreateFuseEntry(FuseContext* context,
                                          fuse_ino_t parent, FileContext entry);

  static void InterruptRequest(fuse_req_t, void* user_data);

  static void Init(void* user_data, struct fuse_conn_info* conn);

  static void Destroy(void* user_data) {}

  static Task<> GetAttr(fuse_req_t req, fuse_ino_t ino, fuse_file_info*);

  static Task<> SetAttr(fuse_req_t req, fuse_ino_t ino, struct stat* attr,
                        int to_set, fuse_file_info* fi);

  static Task<> Open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi);

  static Task<> OpenDir(fuse_req_t req, fuse_ino_t ino, fuse_file_info* fi);

  static Task<> Release(fuse_req_t req, fuse_ino_t ino, fuse_file_info* fi);

  static Task<> ReleaseDir(fuse_req_t req, fuse_ino_t ino, fuse_file_info* fi);

  static Task<> ReadDir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                        fuse_file_info* fi);

  static Task<> Lookup(fuse_req_t req, fuse_ino_t parent,
                       const char* name_c_str);

#ifdef CORO_CLOUDSTORAGE_FUSE2
  using nlookup_t = unsigned long;
#else
  using nlookup_t = uint64_t;
#endif

  static void Forget(fuse_req_t req, fuse_ino_t ino, nlookup_t nlookup);

  static Task<> Read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                     struct fuse_file_info* fi);

  static Task<> Rename2(fuse_req_t req, fuse_ino_t parent,
                        const char* name_c_str, fuse_ino_t new_parent,
                        const char* new_name_c_str);

  static Task<> Rename3(fuse_req_t req, fuse_ino_t parent,
                        const char* name_c_str, fuse_ino_t new_parent,
                        const char* new_name_c_str, unsigned int flags);

  static Task<> MkDir(fuse_req_t req, fuse_ino_t parent, const char* name,
                      mode_t mode);

  static Task<> CreateFile(fuse_req_t req, fuse_ino_t parent, const char* name,
                           mode_t mode, struct fuse_file_info* fi);

  static Task<> Write(fuse_req_t req, fuse_ino_t ino, const char* buf_cstr,
                      size_t size, off_t off, struct fuse_file_info* fi);

  static Task<> Unlink(fuse_req_t req, fuse_ino_t parent,
                       const char* name_c_str);

  static Task<> StatFs(fuse_req_t req, fuse_ino_t ino);

  template <auto F, typename, typename>
  struct CoroutineImpl;

  template <auto F>
  using Coroutine = CoroutineImpl<F, FusePosixContext,
                                  coro::util::ArgumentListTypeT<decltype(F)>>;

  template <auto F>
  static constexpr typename Coroutine<F>::type CoroutineT = Coroutine<F>::Do;

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
  fuse_lowlevel_ops operations_ = GetFuseLowLevelOps();
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
