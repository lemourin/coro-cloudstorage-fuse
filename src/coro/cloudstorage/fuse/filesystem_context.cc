#include "coro/cloudstorage/fuse/filesystem_context.h"

#include <utility>

#include "coro/cloudstorage/util/abstract_cloud_provider_impl.h"

namespace coro::cloudstorage::fuse {

namespace {

using ::coro::cloudstorage::util::CloudProviderAccount;
using ::coro::cloudstorage::util::GetConfigFilePath;
using ::coro::cloudstorage::util::MergedCloudProvider;

struct ForwardToMergedCloudProvider {
  void OnCreate(const std::shared_ptr<CloudProviderAccount>& account) {
    provider->AddAccount(std::string(account->username()), account->provider());
  }

  Task<> OnDestroy(const std::shared_ptr<CloudProviderAccount>& account) {
    provider->RemoveAccount(account->provider());
    co_return;
  }

  MergedCloudProvider* provider;
};

}  // namespace

FileSystemContext::FileSystemContext(const coro::util::EventLoop* event_loop,
                                     Config config)
    : context_(event_loop, config.cache_http_config,
               std::move(config.config_path).value_or(GetConfigFilePath())),
      provider_(CreateAbstractCloudProviderImpl(&merged_provider_)),
      timing_out_provider_(event_loop, config.timeout_ms, &provider_),
      fs_(&timing_out_provider_, context_.thread_pool(), config.fs_config),
      http_server_(context_.CreateHttpServer(
          ForwardToMergedCloudProvider{&merged_provider_})) {}

}  // namespace coro::cloudstorage::fuse
