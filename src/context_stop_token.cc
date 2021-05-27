#include "context_stop_token.h"

namespace coro::cloudstorage::fuse {

TimingOutStopToken::TimingOutStopToken(const coro::util::EventLoop& event_loop,
                                       std::string action, int timeout_ms) {
  coro::Invoke([this, event_loop = &event_loop, action = std::move(action),
                timeout_ms, stop_token = stop_source_.get_token()]() -> Task<> {
    co_await event_loop->Wait(timeout_ms / 4, stop_token);
    if (!stop_token.stop_requested()) {
      std::cerr << action << " TIMING OUT\n";
    } else {
      co_return;
    }
    co_await event_loop->Wait(timeout_ms * 3 / 4, stop_token);
    if (!stop_token.stop_requested()) {
      std::cerr << action << " TIMED OUT\n";
      stop_source_.request_stop();
    }
  });
}

TimingOutStopToken::~TimingOutStopToken() { stop_source_.request_stop(); }

}  // namespace coro::cloudstorage::fuse