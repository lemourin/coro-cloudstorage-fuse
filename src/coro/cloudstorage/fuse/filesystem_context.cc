#include "coro/cloudstorage/fuse/filesystem_context.h"

#include <utility>

#include "coro/cloudstorage/util/abstract_cloud_provider_impl.h"

namespace coro::cloudstorage::fuse {

namespace {

struct ForwardToMergedCloudProvider {
  void OnCreate(util::CloudProviderAccount* account) {
    provider->AddAccount(std::string(account->id()), &account->provider());
  }

  Task<> OnDestroy(util::CloudProviderAccount* account) {
    provider->RemoveAccount(&account->provider());
    co_return;
  }

  util::MergedCloudProvider::CloudProvider* provider;
};


auto GetSettingsManager(util::AbstractCloudFactory* factory,
                        std::optional<std::string> config_path) {
  std::string path = [&] {
    if (config_path) {
      return std::move(*config_path);
    } else {
      return util::GetConfigFilePath();
    }
  }();
  return util::SettingsManager(util::AuthTokenManager{factory, path}, path);
}

}  // namespace

FileSystemContext::FileSystemContext(event_base* event_base, Config config)
    : context_(event_base),
      provider_(util::CreateAbstractCloudProvider(&merged_provider_)),
      timing_out_provider_(context_.event_loop(), config.timeout_ms,
                           provider_.get()),
      fs_(&timing_out_provider_, context_.thread_pool(), config.fs_config),
      http_server_(event_base,
                   GetSettingsManager(context_.factory(), config.config_path)
                       .GetHttpServerConfig(),
                   context_.factory(), context_.thumbnail_generator(),
                   ForwardToMergedCloudProvider{&merged_provider_},
                   GetSettingsManager(context_.factory(), config.config_path)) {
}

}  // namespace coro::cloudstorage::fuse
