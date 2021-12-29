#include "coro/cloudstorage/fuse/filesystem_context.h"

#include <utility>

namespace coro::cloudstorage::fuse {

void FileSystemContext::ForwardToMergedCloudProvider::OnCreate(
    CloudProviderAccountT* account) {
  std::visit([&](auto& d) { provider->AddAccount(account->GetId(), &d); },
             account->provider());
}

Task<> FileSystemContext::ForwardToMergedCloudProvider::OnDestroy(
    CloudProviderAccountT* account) {
  std::visit([&](auto& d) { provider->RemoveAccount(&d); },
             account->provider());
  co_return;
}

FileSystemContext::FileSystemContext(event_base* event_base, Config config)
    : context_(event_base),
      provider_(context_.event_loop(), config.timeout_ms, &merged_provider_),
      fs_(&provider_, context_.thread_pool(), config.fs_config),
      http_server_(
          event_base,
          http::HttpServerConfig{.address = "127.0.0.1", .port = 12345},
          context_.factory(), context_.thumbnail_generator(),
          ForwardToMergedCloudProvider{provider_.GetProvider()},
          util::AuthTokenManager([&] {
            if (config.config_path) {
              return std::move(*config.config_path);
            } else {
              return util::GetConfigFilePath();
            }
          }())) {}

}  // namespace coro::cloudstorage::fuse
