#ifndef CORO_CLOUDSTORAGE_FUSE_ACCOUNT_H
#define CORO_CLOUDSTORAGE_FUSE_ACCOUNT_H

#include <chrono>
#include <optional>

namespace coro::cloudstorage {

template <typename CloudProviderAccount>
class Account {
 public:
  explicit Account(CloudProviderAccount* account) : account_(account) {}

  CloudProviderAccount* account() const { return account_; }
  auto& stop_source() const { return account()->stop_source; }
  auto& provider() const { return account()->provider; }
  auto id() const { return account()->GetId(); }

  std::optional<int64_t> GetTimeToFirstByte() const {
    if (time_to_first_byte_sample_cnt_ == 0) {
      return std::nullopt;
    }
    return time_to_first_byte_sum_ / std::chrono::milliseconds(1) /
           time_to_first_byte_sample_cnt_;
  }

  std::optional<int64_t> GetDownloadSpeed() const {
    if (download_speed_sum_ / std::chrono::milliseconds(1) == 0) {
      return std::nullopt;
    }
    return download_size_ /
           (download_speed_sum_ / std::chrono::milliseconds(1));
  }

  void RegisterTimeToFirstByte(std::chrono::system_clock::duration time) {
    time_to_first_byte_sum_ += time;
    time_to_first_byte_sample_cnt_++;
  }

  void RegisterDownloadSpeed(std::chrono::system_clock::duration time,
                             int64_t chunk_size) {
    download_speed_sum_ += time;
    download_size_ += chunk_size;
  }

 private:
  CloudProviderAccount* account_;
  std::chrono::system_clock::duration time_to_first_byte_sum_ =
      std::chrono::seconds(0);
  int64_t time_to_first_byte_sample_cnt_ = 0;
  std::chrono::system_clock::duration download_speed_sum_ =
      std::chrono::seconds(0);
  int64_t download_size_ = 0;
};

}  // namespace coro::cloudstorage

#endif  // CORO_CLOUDSTORAGE_FUSE_ACCOUNT_H
