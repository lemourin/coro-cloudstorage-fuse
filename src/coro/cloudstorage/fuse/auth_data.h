#ifndef CORO_CLOUDSTORAGE_FUSE_SRC_AUTH_DATA_H
#define CORO_CLOUDSTORAGE_FUSE_SRC_AUTH_DATA_H

#include <coro/cloudstorage/providers/amazon_s3.h>
#include <coro/cloudstorage/providers/box.h>
#include <coro/cloudstorage/providers/dropbox.h>
#include <coro/cloudstorage/providers/google_drive.h>
#include <coro/cloudstorage/providers/mega.h>
#include <coro/cloudstorage/providers/one_drive.h>
#include <coro/cloudstorage/providers/pcloud.h>
#include <coro/cloudstorage/providers/webdav.h>
#include <coro/cloudstorage/providers/yandex_disk.h>

#include <string_view>

namespace coro::cloudstorage::fuse {

struct AuthData {
  static constexpr std::string_view kHostname = "http://localhost:12345";

  template <typename CloudProvider>
  typename CloudProvider::Auth::AuthData operator()() const {
    typename CloudProvider::Auth::AuthData auth_data;
    if constexpr (std::is_same_v<CloudProvider, GoogleDrive>) {
      auth_data = {
          .client_id =
              R"(646432077068-hmvk44qgo6d0a64a5h9ieue34p3j2dcv.apps.googleusercontent.com)",
          .client_secret = "1f0FG5ch-kKOanTAv1Bqdp9U"};
    } else if constexpr (std::is_same_v<CloudProvider, Mega>) {
      auth_data = {.api_key = "ZVhB0Czb", .app_name = "coro-cloudstorage-fuse"};
    } else if constexpr (std::is_same_v<CloudProvider, OneDrive>) {
      auth_data = {.client_id = "56a1d60f-ea71-40e9-a489-b87fba12a23e",
                   .client_secret = "zJRAsd0o4E9c33q4OLc7OhY"};
    } else if constexpr (std::is_same_v<CloudProvider, Dropbox>) {
      auth_data = {.client_id = "ktryxp68ae5cicj",
                   .client_secret = "6evu94gcxnmyr59"};
    } else if constexpr (std::is_same_v<CloudProvider, Box>) {
      auth_data = {
          .client_id = "zmiv9tv13hunxhyjk16zqv8dmdw0d773",
          .client_secret = "IZ0T8WsUpJin7Qt3rHMf7qDAIFAkYZ0R",
      };
    } else if constexpr (std::is_same_v<CloudProvider, YandexDisk>) {
      auth_data = {.client_id = "04d700d432884c4381c07e760213ed8a",
                   .client_secret = "197f9693caa64f0ebb51d201110074f9"};
    } else if constexpr (std::is_same_v<CloudProvider, PCloud>) {
      auth_data = {.client_id = "rjR7bUpwgdz",
                   .client_secret = "zNtirCfoYfmX5aFzoavWikKWyMlV"};
    }
    if constexpr (util::HasRedirectUri<decltype(auth_data)>) {
      auth_data.redirect_uri =
          std::string(kHostname) + "/auth/" + std::string(CloudProvider::kId);
    }
    return auth_data;
  }
};

}  // namespace coro::cloudstorage::fuse

#endif  // CORO_CLOUDSTORAGE_FUSE_SRC_AUTH_DATA_H
