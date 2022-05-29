#include "coro/cloudstorage/fuse/streaming_write.h"

namespace coro::cloudstorage {

CurrentStreamingWrite::CurrentStreamingWrite(
    coro::util::ThreadPool* thread_pool, CloudProvider* provider,
    Directory parent, std::optional<int64_t> size, std::string_view name)
    : thread_pool_(thread_pool),
      provider_(provider),
      parent_(std::move(parent)),
      size_(size),
      name_(name) {
  RunTask([&]() -> Task<> {
    try {
      item_promise_.SetValue(co_await CreateFile());
    } catch (...) {
      item_promise_.SetException(std::current_exception());
    }
  });
}

CurrentStreamingWrite::~CurrentStreamingWrite() { Interrupt(); }

auto CurrentStreamingWrite::Write(std::string_view chunk, int64_t offset,
                                  stdx::stop_token stop_token) -> Task<> {
  if (flushed_) {
    throw CloudException("write after flush");
  }
  if (provider_->IsFileContentSizeRequired(parent_) &&
      current_offset_ + static_cast<int64_t>(chunk.size()) > size_) {
    throw CloudException(util::StrCat("write past declared size ",
                                      size_.value_or(-1),
                                      " (current_offset = ", current_offset_,
                                      ", chunk_size = ", chunk.size(), ")"));
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
  stdx::stop_callback cb(stop_token, [&] { Interrupt(); });
  co_await done_;
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
    co_await done_;
    done_ = Promise<void>();
  };
}

auto CurrentStreamingWrite::Flush(stdx::stop_token stop_token) -> Task<File> {
  if (flushed_) {
    throw CloudException("flush already called");
  }
  flushed_ = true;
  current_chunk_.SetValue(std::string());
  stdx::stop_callback cb(stop_token, [&] { Interrupt(); });
  co_return co_await item_promise_;
}

auto CurrentStreamingWrite::CreateFile() -> Task<File> {
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

auto CurrentStreamingWrite::GetStream() -> Generator<std::string> {
  auto guard =
      coro::util::AtScopeExit([&] { current_chunk_.SetValue(std::string()); });
  while (!flushed_) {
    std::string chunk = co_await current_chunk_;
    current_chunk_ = Promise<std::string>();
    done_.SetValue();
    co_yield std::move(chunk);
  }
  if (provider_->IsFileContentSizeRequired(parent_) &&
      size_ != current_offset_) {
    throw CloudException("incomplete file");
  }
}

void CurrentStreamingWrite::Interrupt() {
  stop_source_.request_stop();
  current_chunk_.SetException(InterruptedException());
}

}  // namespace coro::cloudstorage