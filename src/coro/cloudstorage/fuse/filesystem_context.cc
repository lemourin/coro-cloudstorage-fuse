#include "coro/cloudstorage/fuse/filesystem_context.h"

#include <utility>

#include "coro/cloudstorage/util/abstract_cloud_provider_impl.h"

namespace coro::cloudstorage::fuse {

namespace {

using ::coro::cloudstorage::util::AbstractCloudFactory;
using ::coro::cloudstorage::util::AuthTokenManager;
using ::coro::cloudstorage::util::CreateAbstractCloudProvider;
using ::coro::cloudstorage::util::GetConfigFilePath;
using ::coro::cloudstorage::util::MergedCloudProvider;
using ::coro::cloudstorage::util::SettingsManager;

struct ForwardToMergedCloudProvider {
  void OnCreate(util::CloudProviderAccount* account) {
    provider->AddAccount(std::string(account->id()), &account->provider());
  }

  Task<> OnDestroy(util::CloudProviderAccount* account) {
    provider->RemoveAccount(&account->provider());
    co_return;
  }

  util::MergedCloudProvider* provider;
};

auto GetSettingsManager(AbstractCloudFactory* factory,
                        std::optional<std::string> config_path) {
  std::string path = [&] {
    if (config_path) {
      return std::move(*config_path);
    } else {
      return GetConfigFilePath();
    }
  }();
  return SettingsManager(AuthTokenManager{factory, path}, path);
}

}  // namespace

FileSystemContext::FileSystemContext(const coro::util::EventLoop* event_loop,
                                     Config config)
    : context_(event_loop),
      provider_(CreateAbstractCloudProvider(&merged_provider_)),
      timing_out_provider_(context_.event_loop(), config.timeout_ms,
                           provider_.get()),
      fs_(&timing_out_provider_, context_.thread_pool(), config.fs_config),
      http_server_(context_.event_loop(),
                   GetSettingsManager(context_.factory(), config.config_path)
                       .GetHttpServerConfig(),
                   context_.factory(), context_.thumbnail_generator(),
                   ForwardToMergedCloudProvider{&merged_provider_},
                   GetSettingsManager(context_.factory(), config.config_path)) {
}

}  // namespace coro::cloudstorage::fuse
