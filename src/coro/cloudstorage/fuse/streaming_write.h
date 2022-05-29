#ifndef CORO_CLOUDSTORAGE_FUSE_STREAMING_WRITE_H
#define CORO_CLOUDSTORAGE_FUSE_STREAMING_WRITE_H

#include "coro/cloudstorage/cloud_exception.h"
#include "coro/cloudstorage/fuse/sparse_file.h"
#include "coro/cloudstorage/util/abstract_cloud_provider.h"
#include "coro/cloudstorage/util/file_utils.h"
#include "coro/cloudstorage/util/string_utils.h"
#include "coro/generator.h"
#include "coro/mutex.h"
#include "coro/util/event_loop.h"
#include "coro/util/raii_utils.h"
#include "coro/util/thread_pool.h"

namespace coro::cloudstorage {

class CurrentStreamingWrite {
 public:
  using CloudProvider = util::AbstractCloudProvider::CloudProvider;
  using File = util::AbstractCloudProvider::File;
  using Directory = util::AbstractCloudProvider::Directory;

  CurrentStreamingWrite(coro::util::ThreadPool*, CloudProvider* provider,
                        Directory parent, std::optional<int64_t> size,
                        std::string_view name);
  ~CurrentStreamingWrite();

  CurrentStreamingWrite(const CurrentStreamingWrite&) = delete;
  CurrentStreamingWrite(CurrentStreamingWrite&&) = delete;

  CurrentStreamingWrite& operator=(const CurrentStreamingWrite&) = delete;
  CurrentStreamingWrite& operator=(CurrentStreamingWrite&&) = delete;

  Task<> Write(std::string_view chunk, int64_t offset, stdx::stop_token);
  Task<File> Flush(stdx::stop_token);

 private:
  void Interrupt();
  Generator<std::string> GetStream();
  Task<File> CreateFile();

  coro::util::ThreadPool* thread_pool_;
  CloudProvider* provider_;
  Directory parent_;
  std::optional<int64_t> size_;
  std::string name_;
  bool flushed_ = false;
  Promise<std::string> current_chunk_;
  Promise<void> done_;
  int64_t current_offset_ = 0;
  std::unique_ptr<FILE, util::FileDeleter> buffer_;
  std::vector<Range> ranges_;
  Promise<File> item_promise_;
  Mutex write_mutex_;
  stdx::stop_source stop_source_;
};

}  // namespace coro::cloudstorage

#endif  // CORO_CLOUDSTORAGE_FUSE_STREAMING_WRITE_H
