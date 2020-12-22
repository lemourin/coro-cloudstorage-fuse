#include "fuse_winfsp.h"

#include <coro/cloudstorage/cloud_factory.h>
#include <coro/cloudstorage/providers/dropbox.h>
#include <coro/cloudstorage/providers/google_drive.h>
#include <coro/cloudstorage/providers/mega.h>
#include <coro/cloudstorage/providers/one_drive.h>
#include <coro/cloudstorage/util/account_manager_handler.h>
#include <coro/http/cache_http.h>
#include <coro/http/curl_http.h>
#include <coro/http/http_server.h>
#include <coro/semaphore.h>
#include <coro/task.h>
#include <coro/util/event_loop.h>
#include <event.h>
#include <event2/thread.h>
#include <winfsp/winfsp.h>

#include <future>
#include <iostream>
#include <optional>
#include <string>
#include <thread>

namespace coro::cloudstorage::fuse {

namespace {

const int kAllocationUnit = 4096;

using ::coro::Task;
using ::coro::cloudstorage::CloudException;
using ::coro::cloudstorage::CloudFactory;
using ::coro::cloudstorage::util::AccountManagerHandler;
using ::coro::cloudstorage::util::AuthTokenManager;
using ::coro::cloudstorage::util::MakeAccountManagerHandler;
using ::coro::http::CacheHttp;
using ::coro::http::CurlHttp;
using ::coro::http::HttpServer;
using ::coro::util::EventLoop;
using ::coro::util::TypeList;

using CloudProviders =
    TypeList<coro::cloudstorage::GoogleDrive, coro::cloudstorage::Mega,
             coro::cloudstorage::OneDrive, coro::cloudstorage::Dropbox>;

constexpr std::string_view kTokenFile = "access-token.json";

std::wstring ToWideString(std::string_view string) {
  int size = MultiByteToWideChar(CP_UTF8, 0, string.data(),
                                 static_cast<int>(string.size()), nullptr, 0);
  std::wstring result(size, 0);
  MultiByteToWideChar(CP_UTF8, 0, string.data(),
                      static_cast<int>(string.size()), result.data(), size);
  return result;
}

std::string ToMultiByteString(std::wstring_view string) {
  int size = WideCharToMultiByte(CP_UTF8, 0, string.data(),
                                 static_cast<int>(string.size()), nullptr, 0,
                                 nullptr, nullptr);
  std::string result(size, 0);
  WideCharToMultiByte(CP_UTF8, 0, string.data(),
                      static_cast<int>(string.size()), result.data(), size,
                      nullptr, nullptr);
  return result;
}

std::string ToUnixPath(std::wstring_view string) {
  std::string result = ToMultiByteString(string);
  for (char& c : result) {
    if (c == '\\') {
      c = '/';
    }
  }
  return result;
}

std::wstring ToWindowsPath(std::string_view string) {
  return ToWideString(string);
}

NTSTATUS ToStatus(const CloudException& e) {
  switch (e.type()) {
    case CloudException::Type::kNotFound:
      return STATUS_NOT_FOUND;
    default:
      return STATUS_INVALID_PARAMETER;
  }
}

template <typename T, typename C>
std::vector<T> SplitString(const T& string, C delim) {
  std::vector<T> result;
  T current;
  for (auto c : string) {
    if (c == delim) {
      if (!current.empty()) {
        result.emplace_back(std::move(current));
      }
      current.clear();
    } else {
      current += c;
    }
  }
  if (!current.empty()) {
    result.emplace_back(std::move(current));
  }
  return result;
}

class FileSystemException : public std::exception {
 public:
  explicit FileSystemException(HRESULT status)
      : status_(status), message_(GetErrorString(status)) {}

  HRESULT status() const { return status_; }
  const char* what() const noexcept final { return message_.c_str(); }

 private:
  static std::string GetErrorString(HRESULT r) {
    const int BUFFER_SIZE = 512;
    char buffer[BUFFER_SIZE] = {};
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, nullptr, r, 0, buffer,
                  BUFFER_SIZE, nullptr);
    return buffer;
  }

  HRESULT status_;
  std::string message_;
};

void Check(NTSTATUS status) {
  if (status != S_OK) {
    throw FileSystemException(GetLastError());
  }
}

template <typename>
class WinFspContext;

template <typename... CloudProvider>
class WinFspContext<TypeList<CloudProvider...>> {
 public:
  struct AccountListener;

  using AccountManagerHandlerT =
      AccountManagerHandler<TypeList<CloudProvider...>,
                            CloudFactory<EventLoop, CacheHttp<CurlHttp>>,
                            AccountListener>;
  using CloudProviderAccount =
      typename AccountManagerHandlerT::CloudProviderAccount;

  struct AccountListener {
    void OnCreate(CloudProviderAccount* d) {
      context->accounts_.insert(
          std::shared_ptr<CloudProviderAccount>(d, [](auto) {}));
      std::cerr << "CREATED " << d->id << "\n";
    }
    void OnDestroy(CloudProviderAccount* d) {
      context->accounts_.erase(
          std::shared_ptr<CloudProviderAccount>(d, [](auto) {}));
      std::cerr << "REMOVED " << d->id << "\n";
    }

    WinFspContext* context;
  };

  WinFspContext(PWSTR mountpoint)
      : event_loop_([] {
          evthread_use_windows_threads();
          return event_base_new();
        }()),
        thread_([this] { Main(); }),
        filesystem_([this] {
          FSP_FILE_SYSTEM* filesystem;
          Check(FspFileSystemCreate(
              const_cast<PWSTR>(L"" FSP_FSCTL_NET_DEVICE_NAME), &volume_params_,
              &operations_, &filesystem));
          return filesystem;
        }()),
        dispatcher_([this, mountpoint] {
          Check(FspFileSystemSetMountPoint(filesystem_.get(), mountpoint));
          Check(FspFileSystemStartDispatcher(filesystem_.get(), 0));
          FspFileSystemSetDebugLog(filesystem_.get(), -1);
          return filesystem_.get();
        }()) {
    filesystem_->UserContext = this;
  }

  WinFspContext(const WinFspContext&) = delete;
  WinFspContext(WinFspContext&&) = delete;
  WinFspContext& operator()(const WinFspContext&) = delete;
  WinFspContext& operator()(WinFspContext&&) = delete;

  ~WinFspContext() {
    event_base_once(
        event_loop_.get(), -1, EV_TIMEOUT,
        [](evutil_socket_t, short, void* d) {
          reinterpret_cast<WinFspContext*>(d)->quit_.resume();
        },
        this, nullptr);
    dispatcher_.reset();
    filesystem_.reset();
    thread_.join();
  }

  void Main() {
    Invoke(CoMain(event_loop_.get()));
    event_base_dispatch(event_loop_.get());
  }

  Task<> CoMain(event_base* event_loop) {
    try {
      CacheHttp<CurlHttp> http{CurlHttp(event_loop)};
      CloudFactory cloud_factory(EventLoop(event_loop), http);
      HttpServer http_server(
          event_loop, {.address = "0.0.0.0", .port = 12345},
          AccountManagerHandlerT(
              cloud_factory, AccountListener{this},
              AuthTokenManager{.token_file = std::string(kTokenFile)}));
      co_await quit_;
      co_await http_server.Quit();
      co_return;
    } catch (const std::exception& exception) {
      std::cerr << "EXCEPTION: " << exception.what() << "\n";
    }
  }

 private:
  struct VolumeData {
    int64_t space_used;
    std::optional<int64_t> space_total;
  };

  struct GenericItem {
    std::string name;
    bool is_directory;
    std::optional<int64_t> size;
  };

  template <typename T>
  struct Item {
    using CloudProvider = T;

    Item(std::weak_ptr<CloudProviderAccount> account,
         typename CloudProvider::Item item)
        : account(std::move(account)), item(std::move(item)) {}

    CloudProvider* provider() const {
      auto acc = account.lock();
      if (!acc) {
        throw FileSystemException(STATUS_NOT_FOUND);
      }
      return &std::get<CloudProvider>(acc->provider);
    }

    auto GetGenericItem() const {
      return GenericItem{
          .name = std::visit([](const auto& d) { return d.name; }, item),
          .is_directory =
              std::holds_alternative<typename CloudProvider::Directory>(item),
          .size = std::visit(
              [](const auto& d) {
                if constexpr (std::is_same_v<std::remove_cvref_t<decltype(d)>,
                                             typename CloudProvider::File>) {
                  return d.size;
                } else {
                  return std::optional<int64_t>();
                }
              },
              item)};
    }

    std::weak_ptr<CloudProviderAccount> account;
    typename T::Item item;
  };

  template <typename CloudProvider>
  using ItemT = Item<
      typename CloudProviderAccount::template CloudProviderT<CloudProvider>>;

  using FileContext = std::optional<std::variant<ItemT<CloudProvider>...>>;

  static GenericItem GetGenericItem(const FileContext& ctx) {
    if (!ctx) {
      return GenericItem{.name = "root", .is_directory = true};
    }
    return std::visit([](const auto& d) { return d.GetGenericItem(); }, *ctx);
  }

  static void ToFileInfo(GenericItem item, FSP_FSCTL_FILE_INFO* info) {
    info->FileAttributes =
        item.is_directory ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
    info->FileSize = item.size.value_or(UINT64_MAX);
  }

  std::shared_ptr<CloudProviderAccount> GetAccount(
      std::string_view name) const {
    auto it = std::find_if(accounts_.begin(), accounts_.end(),
                           [name](auto d) { return d->id == name; });
    if (it == accounts_.end()) {
      throw CloudException(CloudException::Type::kNotFound);
    } else {
      return *it;
    }
  }

  Task<FileContext> GetFileContext(std::string path) const {
    auto components = SplitString(path, '/');
    if (components.empty()) {
      co_return FileContext{};
    }
    auto account = GetAccount(*components.begin());
    std::string provider_path;
    for (size_t i = 1; i < components.size(); i++) {
      provider_path += "/" + components[i];
    }
    co_return co_await std::visit(
        [=](auto& d) -> Task<std::variant<ItemT<CloudProvider>...>> {
          using CloudProvider = std::remove_cvref_t<decltype(d)>;
          co_return Item<CloudProvider>(
              account, co_await d.GetItemByPath(provider_path));
        },
        account->provider);
  }

  Generator<std::vector<FileContext>> ReadDirectory(FileContext context) const {
    if (!context) {
      std::vector<FileContext> result;
      for (auto account : accounts_) {
        auto root = co_await std::visit(
            [](auto& provider)
                -> Task<std::variant<typename CloudProvider::Directory...>> {
              co_return co_await provider.GetRoot();
            },
            account->provider);
        std::visit([id = account->id](
                       auto& directory) { directory.name = std::move(id); },
                   root);
        result.emplace_back(std::make_optional(std::visit(
            [&](auto& provider) -> std::variant<ItemT<CloudProvider>...> {
              using CloudProviderT = std::remove_cvref_t<decltype(provider)>;
              return Item<CloudProviderT>(
                  account, std::get<typename CloudProviderT::Directory>(root));
            },
            account->provider)));
      }
      co_yield std::move(result);
      co_return;
    }
    Generator<std::vector<FileContext>> generator = std::visit(
        [](const auto& d) -> Generator<std::vector<FileContext>> {
          using CloudProviderT =
              typename std::remove_cvref_t<decltype(d)>::CloudProvider;
          FOR_CO_AWAIT(
              auto& page_data,
              d.provider()->ListDirectory(
                  std::get<typename CloudProviderT::Directory>(d.item)),
              {
                std::vector<FileContext> page;
                for (auto& item : page_data.items) {
                  page.emplace_back(
                      Item<CloudProviderT>(d.account, std::move(item)));
                }
                co_yield std::move(page);
              });
        },
        *context);

    FOR_CO_AWAIT(std::vector<FileContext> & page_data, generator,
                 { co_yield std::move(page_data); });
  }

  Task<VolumeData> GetVolumeData() const {
    using AnyTask = std::variant<Task<typename CloudProvider::GeneralData>...>;
    std::vector<AnyTask> tasks;
    for (const auto& account : accounts_) {
      tasks.emplace_back(std::visit(
          [](auto& provider) -> AnyTask { return provider.GetGeneralData(); },
          account->provider));
    }
    VolumeData total = {.space_used = 0, .space_total = 0};
    for (auto& task : tasks) {
      auto data = co_await std::visit(
          [&](auto& task) -> Task<VolumeData> {
            auto data = co_await task;
            co_return VolumeData{.space_used = data.space_used,
                                 .space_total = data.space_total};
          },
          task);
      total.space_used += data.space_used;
      if (data.space_total && total.space_total) {
        *total.space_total += *data.space_total;
      } else {
        total.space_total = std::nullopt;
        break;
      }
    }
    co_return total;
  }

  struct EventBaseDeleter {
    void operator()(event_base* event_loop) const {
      event_base_free(event_loop);
    }
  };

  struct FileSystemDeleter {
    void operator()(FSP_FILE_SYSTEM* filesystem) const {
      FspFileSystemDelete(filesystem);
    }
  };

  struct FileSystemDispatcherDeleter {
    void operator()(FSP_FILE_SYSTEM* filesystem) const {
      FspFileSystemStopDispatcher(filesystem);
    }
  };

  template <typename F>
  void RunOnEventLoop(F func) {
    F* data = new F(std::move(func));
    event_base_once(
        event_loop_.get(), -1, EV_TIMEOUT,
        [](evutil_socket_t, short, void* d) {
          Invoke([func = reinterpret_cast<F*>(d)]() -> Task<> {
            co_await (*func)();
            delete func;
          });
        },
        data, nullptr);
  }

  template <typename F>
  auto Do(F func) {
    using ResultType = decltype(func().await_resume());
    std::promise<ResultType> result;
    RunOnEventLoop([&result, &func]() -> Task<> {
      try {
        result.set_value(co_await func());
      } catch (const std::exception&) {
        result.set_exception(std::current_exception());
      }
    });
    return result.get_future().get();
  }

  static NTSTATUS Open(FSP_FILE_SYSTEM* fs, PWSTR filename,
                       UINT32 create_options, UINT32 granted_access,
                       PVOID* file_context, FSP_FSCTL_FILE_INFO* file_info) {
    try {
      auto context = reinterpret_cast<WinFspContext*>(fs->UserContext);
      std::promise<FileContext> result;
      FileContext data = context->Do(
          [=] { return context->GetFileContext(ToUnixPath(filename)); });
      ToFileInfo(GetGenericItem(data), file_info);
      *file_context = new FileContext{std::move(data)};
      return STATUS_SUCCESS;
    } catch (const CloudException& e) {
      return ToStatus(e);
    } catch (const std::exception&) {
      return STATUS_UNHANDLED_EXCEPTION;
    }
  }

  static NTSTATUS GetVolumeInfo(FSP_FILE_SYSTEM* fs,
                                FSP_FSCTL_VOLUME_INFO* volume_info) {
    try {
      auto context = reinterpret_cast<WinFspContext*>(fs->UserContext);

      VolumeData data =
          context->Do([context] { return context->GetVolumeData(); });
      volume_info->FreeSize =
          data.space_total ? *data.space_total - data.space_used : UINT64_MAX;
      volume_info->TotalSize =
          data.space_total ? *data.space_total : UINT64_MAX;
      wcscpy_s(volume_info->VolumeLabel, L"cloudstorage");
      volume_info->VolumeLabelLength =
          static_cast<UINT16>(wcslen(volume_info->VolumeLabel));

      return STATUS_SUCCESS;
    } catch (const CloudException& e) {
      return ToStatus(e);
    } catch (const std::exception&) {
      return STATUS_UNHANDLED_EXCEPTION;
    }
  }

  static VOID Close(FSP_FILE_SYSTEM*, PVOID file_context) {
    delete reinterpret_cast<FileContext*>(file_context);
  }

  static NTSTATUS ReadDirectory(FSP_FILE_SYSTEM* fs, PVOID file_context_ptr,
                                PWSTR pattern, PWSTR marker, PVOID buffer,
                                ULONG buffer_length, PULONG bytes_transferred) {
    auto file_context = reinterpret_cast<FileContext*>(file_context_ptr);
    auto context = reinterpret_cast<WinFspContext*>(fs->UserContext);
    auto hint = FspFileSystemGetOperationContext()->Request->Hint;
    context->RunOnEventLoop([=, file_context = *file_context,
                             bytes_transferred =
                                 *bytes_transferred]() mutable -> Task<> {
      FSP_FSCTL_TRANSACT_RSP response;
      response.Size = sizeof(response);
      response.Kind = FspFsctlTransactQueryDirectoryKind;
      response.Hint = hint;
      response.IoStatus.Information = 0;
      try {
        union {
          UINT8 data[FIELD_OFFSET(FSP_FSCTL_DIR_INFO, FileNameBuf) +
                     MAX_PATH * sizeof(WCHAR)];
          FSP_FSCTL_DIR_INFO d;
        } entry_buffer;
        FSP_FSCTL_DIR_INFO* entry = &entry_buffer.d;
        void* directory_buffer = nullptr;
        std::vector<FileContext> data;
        FOR_CO_AWAIT(std::vector<FileContext> & page_data,
                     context->ReadDirectory(file_context), {
                       for (auto& item : page_data) {
                         data.emplace_back(std::move(item));
                       }
                     });
        NTSTATUS result;
        if (!FspFileSystemAcquireDirectoryBuffer(&directory_buffer, true,
                                                 &result)) {
          response.IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
          FspFileSystemSendResponse(fs, &response);
          co_return;
        }
        std::sort(data.begin(), data.end(), [](const auto& d1, const auto& d2) {
          return GetGenericItem(d1).name < GetGenericItem(d2).name;
        });
        for (const FileContext& d : data) {
          auto item = GetGenericItem(d);
          std::wstring filename = ToWindowsPath(item.name);
          if (marker && filename < marker) {
            continue;
          }
          memcpy(entry->FileNameBuf, filename.c_str(),
                 filename.length() * sizeof(wchar_t));
          memset(&entry->FileInfo, 0, sizeof(entry->FileInfo));
          ToFileInfo(item, &entry->FileInfo);
          entry->Size =
              FIELD_OFFSET(FSP_FSCTL_DIR_INFO, FileNameBuf) +
              static_cast<UINT16>(filename.length() * sizeof(wchar_t));
          if (!FspFileSystemFillDirectoryBuffer(&directory_buffer, entry,
                                                &result)) {
            break;
          }
        }
        FspFileSystemReleaseDirectoryBuffer(&directory_buffer);
        FspFileSystemReadDirectoryBuffer(&directory_buffer, marker, buffer,
                                         buffer_length, &bytes_transferred);
        response.IoStatus.Status = STATUS_SUCCESS;
        response.IoStatus.Information = bytes_transferred;
        FspFileSystemSendResponse(fs, &response);
      } catch (const CloudException& e) {
        response.IoStatus.Status = ToStatus(e);
        FspFileSystemSendResponse(fs, &response);
      } catch (const std::exception&) {
        response.IoStatus.Status = STATUS_UNHANDLED_EXCEPTION;
        FspFileSystemSendResponse(fs, &response);
      }
    });
    return STATUS_PENDING;
  }

  static NTSTATUS Create(FSP_FILE_SYSTEM* fs, PWSTR filename,
                         UINT32 create_options, UINT32 granted_access,
                         UINT32 file_attributes,
                         PSECURITY_DESCRIPTOR security_descriptor,
                         UINT64 allocation_size, PVOID* file_context,
                         FSP_FSCTL_FILE_INFO* file_info) {
    return STATUS_NOT_IMPLEMENTED;
  }

  static NTSTATUS Overwrite(FSP_FILE_SYSTEM* fs, PVOID file_context,
                            UINT32 file_attributes,
                            BOOLEAN replace_file_attributes,
                            UINT64 allocation_size,
                            FSP_FSCTL_FILE_INFO* file_info) {
    return STATUS_NOT_IMPLEMENTED;
  }

  static NTSTATUS Read(FSP_FILE_SYSTEM* fs, PVOID file_context, PVOID buffer,
                       UINT64 offset, ULONG length, PULONG bytes_transferred) {
    auto context = static_cast<WinFspContext*>(fs->UserContext);
    auto file = static_cast<FileContext*>(file_context);
    auto hint = FspFileSystemGetOperationContext()->Request->Hint;
    if (!file) {
      return STATUS_INVALID_PARAMETER;
    }
    if (static_cast<int64_t>(offset) >=
        GetGenericItem(*file).size.value_or(0)) {
      return STATUS_END_OF_FILE;
    }
    context->RunOnEventLoop([=]() -> Task<> {
      std::cerr << "READ " << offset << " " << length << "\n";
      FSP_FSCTL_TRANSACT_RSP response;
      memset(&response, 0, sizeof(response));
      response.Size = sizeof(response);
      response.Kind = FspFsctlTransactReadKind;
      response.Hint = hint;
      response.IoStatus.Information = 0;
      try {
        Generator<std::string> generator = std::visit(
            [=](const auto& d) {
              using CloudProviderT =
                  typename std::remove_cvref_t<decltype(d)>::CloudProvider;
              const auto& item =
                  std::get<typename CloudProviderT::File>(d.item);
              if (!item.size) {
                throw CloudException("size unknown");
              }
              return d.provider()->GetFileContent(
                  item,
                  http::Range{.start = static_cast<int64_t>(offset),
                              .end = std::min<int64_t>(
                                  *item.size - 1,
                                  static_cast<int64_t>(offset + length - 1))});
            },
            **file);
        std::string body = co_await http::GetBody(std::move(generator));
        memcpy(buffer, body.c_str(), body.size());
        response.IoStatus.Status = STATUS_SUCCESS;
        response.IoStatus.Information = static_cast<uint32_t>(body.size());
        FspFileSystemSendResponse(fs, &response);
      } catch (const CloudException& e) {
        response.IoStatus.Status = ToStatus(e);
        FspFileSystemSendResponse(fs, &response);
      } catch (const std::exception&) {
        response.IoStatus.Status = STATUS_UNHANDLED_EXCEPTION;
        FspFileSystemSendResponse(fs, &response);
      }
    });
    return STATUS_PENDING;
  }

  static VOID Cleanup(FSP_FILE_SYSTEM* fs, PVOID file_context, PWSTR file_name,
                      ULONG flags) {}

  FSP_FSCTL_VOLUME_PARAMS volume_params_ = {.SectorSize = kAllocationUnit,
                                            .SectorsPerAllocationUnit = 1,
                                            .MaxComponentLength = MAX_PATH,
                                            .VolumeSerialNumber = 1,
                                            .FileInfoTimeout = ~0u,
                                            .CaseSensitiveSearch = 1,
                                            .CasePreservedNames = 1,
                                            .UnicodeOnDisk = 1,
                                            .ReadOnlyVolume = 1,
                                            .UmFileContextIsUserContext2 = 1,
                                            .Prefix = L"\\cloud\\share",
                                            .FileSystemName = L"cloud"};
  FSP_FILE_SYSTEM_INTERFACE operations_ = {.GetVolumeInfo = GetVolumeInfo,
                                           .SetVolumeLabel = nullptr,
                                           .GetSecurityByName = nullptr,
                                           .Create = Create,
                                           .Open = Open,
                                           .Overwrite = Overwrite,
                                           .Cleanup = Cleanup,
                                           .Close = Close,
                                           .Read = Read,
                                           .Write = nullptr,
                                           .Flush = nullptr,
                                           .GetFileInfo = nullptr,
                                           .SetBasicInfo = nullptr,
                                           .SetFileSize = nullptr,
                                           .CanDelete = nullptr,
                                           .Rename = nullptr,
                                           .GetSecurity = nullptr,
                                           .SetSecurity = nullptr,
                                           .ReadDirectory = ReadDirectory};

  coro::Semaphore quit_;
  std::unique_ptr<event_base, EventBaseDeleter> event_loop_;
  std::thread thread_;
  std::unique_ptr<FSP_FILE_SYSTEM, FileSystemDeleter> filesystem_;
  std::unique_ptr<FSP_FILE_SYSTEM, FileSystemDispatcherDeleter> dispatcher_;
  std::set<std::shared_ptr<CloudProviderAccount>> accounts_;
};

NTSTATUS SvcStart(FSP_SERVICE* service, ULONG argc, PWSTR* argv) {
  try {
    if (argc != 2) {
      return STATUS_INVALID_PARAMETER;
    }
    service->UserContext = new WinFspContext<CloudProviders>(argv[1]);
    return STATUS_SUCCESS;
  } catch (const FileSystemException& e) {
    std::cerr << e.what() << "\n";
    return e.status();
  }
}

NTSTATUS SvcStop(FSP_SERVICE* service) {
  delete reinterpret_cast<WinFspContext<CloudProviders>*>(service->UserContext);
  return STATUS_SUCCESS;
}

}  // namespace

int RunWinFSP() {
  if (!NT_SUCCESS(FspLoad(nullptr))) {
    return ERROR_DELAY_LOAD_FAILED;
  }

  return FspServiceRun(const_cast<wchar_t*>(L"coro-cloudstorage-fuse"),
                       SvcStart, SvcStop, nullptr);
}

}  // namespace coro::cloudstorage::fuse
