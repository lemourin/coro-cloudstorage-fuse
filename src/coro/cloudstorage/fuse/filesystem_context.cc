#include "filesystem_context.h"

namespace coro::cloudstorage::fuse {

void FileSystemContext::ForwardToMergedCloudProvider::OnCreate(
    CloudProviderAccountT* account) {
  std::visit([&](auto& d) { provider->AddAccount(account->GetId(), &d); },
             account->provider);
}

void FileSystemContext::ForwardToMergedCloudProvider::OnDestroy(
    CloudProviderAccountT* account) {
  std::visit([&](auto& d) { provider->RemoveAccount(&d); }, account->provider);
}

FileSystemContext::FileSystemContext(event_base* event_base, Config config)
    : event_loop_(event_base),
      thread_pool_(event_loop_),
      http_(http::CurlHttp(event_base)),
      thumbnail_generator_(&thread_pool_, &event_loop_),
      muxer_(&event_loop_, &thread_pool_),
      factory_(event_loop_, http_, thumbnail_generator_, muxer_),
      provider_(&event_loop_, config.timeout_ms, MergedCloudProviderT()),
      fs_(&provider_, &event_loop_, &thread_pool_, config.fs_config),
      http_server_(
          event_base,
          http::HttpServerConfig{.address = "127.0.0.1", .port = 12345},
          AccountManagerHandlerT(
              factory_, thumbnail_generator_,
              ForwardToMergedCloudProvider{provider_.GetProvider()},
              util::AuthTokenManager([&] {
                if (config.config_path) {
                  return std::move(*config.config_path);
                } else {
                  return util::GetConfigFilePath();
                }
              }()))) {}

}  // namespace coro::cloudstorage::fuse