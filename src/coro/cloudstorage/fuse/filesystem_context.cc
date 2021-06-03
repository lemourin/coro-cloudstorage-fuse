#include "filesystem_context.h"

namespace coro::cloudstorage::fuse {

void FileSystemContext::ForwardToMergedCloudProvider::OnCreate(
    CloudProviderAccountT* account) {
  if constexpr (!kTestCloudProvider) {
    std::visit([&](auto& d) { provider->AddAccount(account->GetId(), &d); },
               account->provider);
  }
}

Task<> FileSystemContext::ForwardToMergedCloudProvider::OnDestroy(
    CloudProviderAccountT* account) {
  if constexpr (!kTestCloudProvider) {
    std::visit([&](auto& d) { provider->RemoveAccount(&d); },
               account->provider);
  }
  co_return;
}

FileSystemContext::FileSystemContext(event_base* event_base, Config config)
    : event_loop_(event_base),
      thread_pool_(event_loop_),
      http_(http::CurlHttp(event_base)),
      thumbnail_generator_(&thread_pool_, &event_loop_),
      muxer_(&event_loop_, &thread_pool_),
      factory_(event_loop_, http_, thumbnail_generator_, muxer_),
      provider_([&] {
        if constexpr (kTestCloudProvider) {
          return CreateCloudProvider<TestCloudProviderT>(factory_);
        } else {
          return CloudProviderT(&event_loop_, config.timeout_ms,
                                &merged_provider_);
        }
      }()),
      fs_(&provider_, &event_loop_, &thread_pool_, config.fs_config),
      http_server_(
          event_base,
          http::HttpServerConfig{.address = "127.0.0.1", .port = 12345},
          AccountManagerHandlerT(factory_, thumbnail_generator_,
                                 ForwardToMergedCloudProvider{[&] {
                                   if constexpr (kTestCloudProvider) {
                                     return nullptr;
                                   } else {
                                     return provider_.GetProvider();
                                   }
                                 }()},
                                 util::AuthTokenManager([&] {
                                   if (config.config_path) {
                                     return std::move(*config.config_path);
                                   } else {
                                     return util::GetConfigFilePath();
                                   }
                                 }()))) {}

}  // namespace coro::cloudstorage::fuse