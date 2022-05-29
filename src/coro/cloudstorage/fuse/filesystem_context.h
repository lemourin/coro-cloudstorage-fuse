#ifndef CORO_CLOUDSTORAGE_FUSE_FILESYSTEM_CONTEXT_H
#define CORO_CLOUDSTORAGE_FUSE_FILESYSTEM_CONTEXT_H

#include "coro/cloudstorage/cloud_factory.h"
#include "coro/cloudstorage/fuse/auth_data.h"
#include "coro/cloudstorage/fuse/filesystem_provider.h"
#include "coro/cloudstorage/util/account_manager_handler.h"
#include "coro/cloudstorage/util/cloud_factory_context.h"
#include "coro/cloudstorage/util/merged_cloud_provider.h"
#include "coro/cloudstorage/util/muxer.h"
#include "coro/cloudstorage/util/random_number_generator.h"
#include "coro/cloudstorage/util/thumbnail_generator.h"
#include "coro/cloudstorage/util/timing_out_cloud_provider.h"
#include "coro/http/cache_http.h"
#include "coro/http/curl_http.h"
#include "coro/http/http_server.h"
#include "coro/util/event_loop.h"

namespace coro::cloudstorage::fuse {

class FileSystemContext {
 public:
  struct Config {
    int timeout_ms;
    std::optional<std::string> config_path;
    FileSystemProviderConfig fs_config;
  };

  using FileSystemProviderT =
      FileSystemProvider<util::AbstractCloudProvider::CloudProvider,
                         coro::util::ThreadPool>;

  explicit FileSystemContext(event_base*, Config = {.timeout_ms = 10000});

  const FileSystemProviderT& fs() const { return fs_; }
  FileSystemProviderT& fs() { return fs_; }

  Task<> Quit() { return http_server_.Quit(); }

 private:
  util::CloudFactoryContext context_;
  util::MergedCloudProvider::CloudProvider merged_provider_;
  std::unique_ptr<util::AbstractCloudProvider::CloudProvider> provider_;
  util::TimingOutCloudProvider timing_out_provider_;
  FileSystemProviderT fs_;
  coro::http::HttpServer<util::AccountManagerHandler> http_server_;
};

}  // namespace coro::cloudstorage::fuse

#endif  // CORO_CLOUDSTORAGE_FUSE_FILESYSTEM_CONTEXT_H
