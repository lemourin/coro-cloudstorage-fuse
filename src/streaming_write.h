#ifndef CORO_CLOUDSTORAGE_FUSE_STREAMING_WRITE_H
#define CORO_CLOUDSTORAGE_FUSE_STREAMING_WRITE_H

#include <coro/mutex.h>
#include <coro/util/event_loop.h>
#include <coro/util/thread_pool.h>

namespace coro::cloudstorage {

template <typename CloudProvider, typename Directory>
class CurrentStreamingWrite {
 public:
  using File = typename decltype(std::declval<CloudProvider>().CreateFile(
      std::declval<Directory>(), std::string_view(),
      std::declval<typename CloudProvider::FileContent>(),
      stdx::stop_token()))::type;

  CurrentStreamingWrite(coro::util::ThreadPool*, coro::util::EventLoop*,
                        CloudProvider* provider, Directory parent,
                        std::optional<int64_t> size, std::string_view name);

  Task<> Write(std::string_view chunk, int64_t offset, stdx::stop_token);
  Task<File> Flush(stdx::stop_token);

 private:
  Generator<std::string> GetStream();
  Task<File> CreateFile();

  coro::util::ThreadPool* thread_pool_;
  coro::util::EventLoop* event_loop_;
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

template <typename CloudProvider, typename Directory>
CurrentStreamingWrite<CloudProvider, Directory>::CurrentStreamingWrite(
    coro::util::ThreadPool* thread_pool, coro::util::EventLoop* event_loop,
    CloudProvider* provider, Directory parent, std::optional<int64_t> size,
    std::string_view name)
    : thread_pool_(thread_pool),
      event_loop_(event_loop),
      provider_(provider),
      parent_(std::move(parent)),
      size_(size),
      name_(name) {
  Invoke([&]() -> Task<> {
    try {
      item_promise_.SetValue(co_await CreateFile());
    } catch (...) {
      item_promise_.SetException(std::current_exception());
    }
  });
}

template <typename CloudProvider, typename Directory>
auto CurrentStreamingWrite<CloudProvider, Directory>::Write(
    std::string_view chunk, int64_t offset, stdx::stop_token stop_token)
    -> Task<> {
  if (flushed_) {
    throw CloudException("write after flush");
  }
  if (CloudProvider::kIsFileContentSizeRequired &&
      current_offset_ + static_cast<int64_t>(chunk.size()) > size_) {
    throw CloudException("write past declared size");
  }
  auto lock = co_await UniqueLock::Create(&write_mutex_);
  if (current_offset_ != offset) {
    if (!buffer_) {
      buffer_ = util::CreateTmpFile();
    }
    co_await util::WriteFile(thread_pool_, buffer_.get(), offset, chunk);
    ranges_.emplace_back(Range{.offset = offset, .size = chunk.size()});
    co_return;
  }
  current_offset_ += chunk.size();
  current_chunk_.SetValue(std::string(chunk));
  co_await InterruptibleAwait(done_, stop_token);
  done_ = Promise<void>();
  while (true) {
    auto it = std::find_if(ranges_.begin(), ranges_.end(), [&](const auto& d) {
      return d.offset == current_offset_;
    });
    if (it == ranges_.end()) {
      break;
    }
    current_chunk_.SetValue(co_await util::ReadFile(thread_pool_, buffer_.get(),
                                                    it->offset, it->size));
    current_offset_ += it->size;
    co_await InterruptibleAwait(done_, stop_token);
    done_ = Promise<void>();
  };
}

template <typename CloudProvider, typename Directory>
auto CurrentStreamingWrite<CloudProvider, Directory>::Flush(
    stdx::stop_token stop_token) -> Task<File> {
  if (flushed_) {
    throw CloudException("flush already called");
  }
  flushed_ = true;
  current_chunk_.SetValue(std::string());
  co_return co_await InterruptibleAwait(item_promise_, std::move(stop_token));
}

template <typename CloudProvider, typename Directory>
auto CurrentStreamingWrite<CloudProvider, Directory>::CreateFile()
    -> Task<File> {
  try {
    typename CloudProvider::FileContent content{.data = GetStream()};
    if (size_) {
      content.size = *size_;
    }
    auto item = co_await provider_->CreateFile(
        parent_, name_, std::move(content), stop_source_.get_token());
    current_chunk_.SetException(CloudException("unexpected short write"));
    done_.SetException(CloudException("unexpected short write"));
    co_return item;
  } catch (...) {
    done_.SetException(std::current_exception());
    current_chunk_.SetException(std::current_exception());
    throw;
  }
}

template <typename CloudProvider, typename Directory>
auto CurrentStreamingWrite<CloudProvider, Directory>::GetStream()
    -> Generator<std::string> {
  while (!flushed_) {
    std::string chunk =
        co_await InterruptibleAwait(current_chunk_, stop_source_.get_token());
    current_chunk_ = Promise<std::string>();
    done_.SetValue();
    co_yield std::move(chunk);
  }
  if (CloudProvider::kIsFileContentSizeRequired && size_ != current_offset_) {
    throw CloudException("incomplete file");
  }
}

}  // namespace coro::cloudstorage

#endif  // CORO_CLOUDSTORAGE_FUSE_STREAMING_WRITE_H
