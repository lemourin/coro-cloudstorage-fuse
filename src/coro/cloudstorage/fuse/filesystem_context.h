#ifndef CORO_CLOUDSTORAGE_FUSE_FILESYSTEM_CONTEXT_H
#define CORO_CLOUDSTORAGE_FUSE_FILESYSTEM_CONTEXT_H

#include <coro/cloudstorage/cloud_factory.h>
#include <coro/cloudstorage/fuse/filesystem_provider.h>
#include <coro/cloudstorage/providers/amazon_s3.h>
#include <coro/cloudstorage/providers/box.h>
#include <coro/cloudstorage/providers/dropbox.h>
#include <coro/cloudstorage/providers/google_drive.h>
#include <coro/cloudstorage/providers/mega.h>
#include <coro/cloudstorage/providers/one_drive.h>
#include <coro/cloudstorage/providers/pcloud.h>
#include <coro/cloudstorage/providers/webdav.h>
#include <coro/cloudstorage/providers/yandex_disk.h>
#include <coro/cloudstorage/util/account_manager_handler.h>
#include <coro/cloudstorage/util/merged_cloud_provider.h>
#include <coro/cloudstorage/util/muxer.h>
#include <coro/cloudstorage/util/thumbnail_generator.h>
#include <coro/cloudstorage/util/timing_out_cloud_provider.h>
#include <coro/http/cache_http.h>
#include <coro/http/curl_http.h>
#include <coro/http/http_server.h>
#include <coro/util/event_loop.h>

namespace coro::cloudstorage::fuse {

class FileSystemContext {
 private:
  struct Config {
    int timeout_ms;
    std::optional<std::string> config_path;
    FileSystemProviderConfig fs_config;
  };

  struct ForwardToMergedCloudProvider;

  using CloudProviderTypeList =
      coro::util::TypeList<GoogleDrive, Mega, AmazonS3, Box, Dropbox, OneDrive,
                           PCloud, WebDAV, YandexDisk>;
  using HttpT = http::CacheHttp<http::CurlHttp>;
  using CloudFactoryT = CloudFactory<coro::util::EventLoop, HttpT,
                                     util::ThumbnailGenerator, util::Muxer>;
  using AccountManagerHandlerT =
      util::AccountManagerHandler<CloudProviderTypeList, CloudFactoryT,
                                  util::ThumbnailGenerator,
                                  ForwardToMergedCloudProvider>;
  using MergedCloudProviderT = util::MergedCloudProvider<
      AccountManagerHandlerT::CloudProviderAccount::Ts>::CloudProvider;
  using CloudProviderAccountT = AccountManagerHandlerT::CloudProviderAccount;

  struct ForwardToMergedCloudProvider {
    void OnCreate(CloudProviderAccountT* account);
    void OnDestroy(CloudProviderAccountT* account);

    MergedCloudProviderT* provider;
  };

 public:
  using CloudProviderT = util::TimingOutCloudProvider<MergedCloudProviderT>::CloudProvider;
  using FileSystemProviderT = FileSystemProvider<CloudProviderT>;

  explicit FileSystemContext(event_base*, Config = {.timeout_ms = 10000});

  const FileSystemProviderT& fs() const { return fs_; }
  FileSystemProviderT& fs() { return fs_; }

  template <typename F>
  void RunOnEventLoop(F f) {
    event_loop_.RunOnEventLoop(std::move(f));
  }
  Task<> Quit() { return http_server_.Quit(); }

 private:
  coro::util::EventLoop event_loop_;
  coro::util::ThreadPool thread_pool_;
  HttpT http_;
  coro::cloudstorage::util::ThumbnailGenerator thumbnail_generator_;
  coro::cloudstorage::util::Muxer muxer_;
  CloudFactoryT factory_;
  CloudProviderT provider_;
  FileSystemProviderT fs_;
  coro::http::HttpServer<AccountManagerHandlerT> http_server_;
};

template <typename CloudProvider, typename Factory>
auto CreateCloudProvider(const Factory& factory) {
  using ::coro::cloudstorage::util::AuthToken;
  using ::coro::cloudstorage::util::AuthTokenManager;

  auto token = std::get<AuthToken<CloudProvider>>(
      AuthTokenManager()
          .LoadTokenData<coro::util::TypeList<CloudProvider>>()
          .front());
  return factory.template Create<CloudProvider>(
      token, [id = std::move(token.id)](const auto& new_token) {
        AuthTokenManager().template SaveToken<CloudProvider>(new_token, id);
      });
}

template <typename CloudProvider, typename Factory>
using CloudProviderT =
    decltype(CreateCloudProvider<CloudProvider>(std::declval<Factory>()));

}  // namespace coro::cloudstorage::fuse

#endif  // CORO_CLOUDSTORAGE_FUSE_FILESYSTEM_CONTEXT_H
