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

template <typename ThreadPool>
class SparseFile {
 public:
  explicit SparseFile(ThreadPool* thread_pool)
      : thread_pool_(thread_pool), file_(util::CreateTmpFile()) {}

  Task<> Write(int64_t offset, std::string_view chunk) {
    auto lock = co_await UniqueLock::Create(&mutex_);
    co_await util::WriteFile(thread_pool_, file_.get(), offset, chunk);
    Range range{.offset = offset, .size = chunk.size()};
    if (ranges_.empty()) {
      ranges_.insert(range);
    } else {
      auto it = ranges_.upper_bound(Range{
          .offset = offset, .size = (std::numeric_limits<size_t>::max)()});
      while (it != ranges_.end() &&
             Intersects(Range{.offset = it->offset - 1, .size = it->size},
                        range)) {
        range = Add(range, *it);
        it = ranges_.erase(it);
      }
      if (!ranges_.empty() && it != ranges_.begin()) {
        it = std::prev(it);
        while (it != ranges_.end() &&
               Intersects(Range{.offset = it->offset, .size = it->size + 1},
                          range)) {
          range = Add(range, *it);
          it = ranges_.erase(it);
          if (!ranges_.empty() && it != ranges_.begin()) {
            it = std::prev(it);
          } else {
            break;
          }
        }
      }
      ranges_.insert(range);
    }
  }

  Task<std::optional<std::string>> Read(int64_t offset, size_t size) const {
    auto it = ranges_.upper_bound(
        Range{.offset = offset, .size = (std::numeric_limits<size_t>::max)()});
    if (ranges_.empty() || it == ranges_.begin()) {
      co_return std::nullopt;
    }
    if (IsInside(Range{.offset = offset, .size = size}, *std::prev(it))) {
      auto lock = co_await UniqueLock::Create(&mutex_);
      co_return co_await util::ReadFile(thread_pool_, file_.get(), offset, size);
    } else {
      co_return std::nullopt;
    }
  }

 private:
  static Range Add(const Range& r1, const Range& r2) {
    return Range{
        .offset = std::min<int64_t>(r1.offset, r2.offset),
        .size = static_cast<size_t>(
            std::max<int64_t>(r1.offset + r1.size, r2.offset + r2.size) -
            std::min<int64_t>(r1.offset, r2.offset))};
  }

  static bool Intersects(const Range& r1, const Range& r2) {
    return std::max<int64_t>(r1.offset, r2.offset) <=
           std::min<int64_t>(r1.offset + r1.size, r2.offset + r2.size);
  }

  static bool IsInside(const Range& r1, const Range& r2) {
    return r1.offset >= r2.offset && r1.offset + r1.size <= r2.offset + r2.size;
  }

  ThreadPool* thread_pool_;
  std::set<Range> ranges_;
  std::unique_ptr<FILE, util::FileDeleter> file_;
  mutable Mutex mutex_;
};

}  // namespace coro::cloudstorage

#endif  // CORO_CLOUDSTORAGE_FUSE_SPARSE_FILE_H
