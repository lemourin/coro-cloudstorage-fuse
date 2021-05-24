#include "new_filesystem_context.h"

namespace coro::cloudstorage::fuse {

void NewFileSystemContext::ForwardToMergedCloudProvider::OnCreate(
    CloudProviderAccountT* account) {
  std::visit([&](auto& d) { provider->AddAccount(account->GetId(), &d); },
             account->provider);
}

void NewFileSystemContext::ForwardToMergedCloudProvider::OnDestroy(
    CloudProviderAccountT* account) {
  std::visit([&](auto& d) { provider->RemoveAccount(&d); }, account->provider);
}

NewFileSystemContext::NewFileSystemContext(event_base* event_base)
    : event_loop_(event_base),
      thread_pool_(event_loop_),
      http_(http::CurlHttp(event_base)),
      thumbnail_generator_(&thread_pool_, &event_loop_),
      muxer_(&event_loop_, &thread_pool_),
      factory_(event_loop_, http_, thumbnail_generator_, muxer_),
      fs_(&provider_, &event_loop_, &thread_pool_),
      http_server_(
          event_base,
          http::HttpServerConfig{.address = "127.0.0.1", .port = 12345},
          AccountManagerHandlerT(factory_, thumbnail_generator_,
                                 ForwardToMergedCloudProvider{&provider_})) {}

}  // namespace coro::cloudstorage::fuse