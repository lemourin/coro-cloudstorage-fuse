#include "coro/cloudstorage/fuse/sparse_file.h"

namespace coro::cloudstorage {

namespace {

Range Add(const Range& r1, const Range& r2) {
  return Range{.offset = std::min<int64_t>(r1.offset, r2.offset),
               .size = static_cast<size_t>(
                   std::max<int64_t>(r1.offset + r1.size, r2.offset + r2.size) -
                   std::min<int64_t>(r1.offset, r2.offset))};
}

bool Intersects(const Range& r1, const Range& r2) {
  return std::max<int64_t>(r1.offset, r2.offset) <=
         std::min<int64_t>(r1.offset + r1.size, r2.offset + r2.size);
}

bool IsInside(const Range& r1, const Range& r2) {
  return r1.offset >= r2.offset && r1.offset + r1.size <= r2.offset + r2.size;
}

}  // namespace

SparseFile::SparseFile(coro::util::ThreadPool* thread_pool)
    : thread_pool_(thread_pool), file_(util::CreateTmpFile()) {}

Task<> SparseFile::Write(int64_t offset, std::string_view chunk) {
  auto lock = co_await UniqueLock::Create(&mutex_);
  co_await util::WriteFile(thread_pool_, file_.get(), offset, chunk);
  Range range{.offset = offset, .size = chunk.size()};
  if (ranges_.empty()) {
    ranges_.insert(range);
  } else {
    auto it = ranges_.upper_bound(
        Range{.offset = offset, .size = (std::numeric_limits<size_t>::max)()});
    while (
        it != ranges_.end() &&
        Intersects(Range{.offset = it->offset - 1, .size = it->size}, range)) {
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

Task<std::optional<std::string>> SparseFile::Read(int64_t offset,
                                                  size_t size) const {
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

}  // namespace coro::cloudstorage