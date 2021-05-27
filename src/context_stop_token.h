#ifndef CORO_CLOUDSTORAGE_FUSE_CONTEXT_STOP_TOKEN_H
#define CORO_CLOUDSTORAGE_FUSE_CONTEXT_STOP_TOKEN_H

#include <coro/stdx/stop_token.h>
#include <coro/task.h>
#include <coro/util/event_loop.h>
#include <coro/util/stop_token_or.h>

#include <iostream>
#include <string>

namespace coro::cloudstorage::fuse {

class TimingOutStopToken {
 public:
  TimingOutStopToken(const coro::util::EventLoop& event_loop,
                     std::string action, int timeout_ms);
  ~TimingOutStopToken();

  stdx::stop_token GetToken() const { return stop_source_.get_token(); }

 private:
  stdx::stop_source stop_source_;
};

class ContextStopToken {
 public:
  ContextStopToken(const coro::util::EventLoop& event_loop, std::string action,
                   int timeout_ms, stdx::stop_token account_token,
                   stdx::stop_token query_token)
      : fst_(std::move(account_token), std::move(query_token)),
        timing_out_stop_token_(event_loop, std::move(action), timeout_ms),
        nd_(fst_.GetToken(), timing_out_stop_token_.GetToken()) {}

  stdx::stop_token GetToken() const { return nd_.GetToken(); }

 private:
  coro::util::StopTokenOr fst_;
  TimingOutStopToken timing_out_stop_token_;
  coro::util::StopTokenOr nd_;
};

}  // namespace coro::cloudstorage::fuse

#endif  // CORO_CLOUDSTORAGE_FUSE_CONTEXT_STOP_TOKEN_H
