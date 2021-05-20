#ifndef CORO_CLOUDSTORAGE_FUSE_SPARSE_FILE_H
#define CORO_CLOUDSTORAGE_FUSE_SPARSE_FILE_H

#include <coro/cloudstorage/util/file_utils.h>
#include <coro/mutex.h>
#include <coro/task.h>
#include <coro/util/thread_pool.h>

#include <set>

namespace coro::cloudstorage {

struct Range {
  int64_t offset;
  size_t size;

  bool operator<(const Range& other) const {
    return std::tie(offset, size) < std::tie(other.offset, other.size);
  }
};

class SparseFile {
 public:
  explicit SparseFile(coro::util::ThreadPool*);

  Task<> Write(int64_t offset, std::string_view chunk);
  Task<std::optional<std::string>> Read(int64_t offset, size_t size) const;

 private:
  coro::util::ThreadPool* thread_pool_;
  std::set<Range> ranges_;
  std::unique_ptr<FILE, util::FileDeleter> file_;
  mutable Mutex mutex_;
};

}  // namespace coro::cloudstorage

#endif  // CORO_CLOUDSTORAGE_FUSE_SPARSE_FILE_H
