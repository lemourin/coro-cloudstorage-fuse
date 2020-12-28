#include "fuse_winfsp.h"

// clang-format off
#include "filesystem_context.h"
// clang-format on

#include <winfsp/winfsp.h>

#include <future>
#include <iostream>
#include <optional>
#include <string>

namespace coro::cloudstorage::fuse {

namespace {

const int kAllocationUnit = 4096;

using ::coro::Task;
using ::coro::cloudstorage::CloudException;

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

class WinFspContext {
 public:
  using FileContext = FileSystemContext::FileContext;
  using GenericItem = FileSystemContext::GenericItem;

  WinFspContext(PWSTR mountpoint)
      : filesystem_([this] {
          FSP_FILE_SYSTEM* filesystem;
          Check(FspFileSystemCreate(
              const_cast<PWSTR>(L"" FSP_FSCTL_NET_DEVICE_NAME), &volume_params_,
              &operations_, &filesystem));
          return filesystem;
        }()),
        dispatcher_([this, mountpoint] {
          Check(FspFileSystemSetMountPoint(filesystem_.get(), mountpoint));
          Check(FspFileSystemStartDispatcher(filesystem_.get(), 0));
          return filesystem_.get();
        }()) {
    filesystem_->UserContext = &context_;
  }

 private:
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

  static void ToFileInfo(GenericItem item, FSP_FSCTL_FILE_INFO* info) {
    info->FileAttributes =
        item.is_directory ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
    info->FileSize = item.size.value_or(UINT64_MAX);
    info->ChangeTime =
        item.timestamp ? 10000000ULL * *item.timestamp + 116444736000000000ULL
                       : 0;
    info->CreationTime = info->ChangeTime;
    info->LastAccessTime = info->ChangeTime;
    info->LastWriteTime = info->ChangeTime;
    info->IndexNumber = 0;
    info->HardLinks = 0;
    info->ReparseTag = 0;
    info->AllocationSize = item.size ? (*item.size + kAllocationUnit - 1) /
                                           kAllocationUnit * kAllocationUnit
                                     : UINT64_MAX;
  }

  static NTSTATUS Open(FSP_FILE_SYSTEM* fs, PWSTR filename,
                       UINT32 create_options, UINT32 granted_access,
                       PVOID* file_context, FSP_FSCTL_FILE_INFO* file_info) {
    try {
      auto context = reinterpret_cast<FileSystemContext*>(fs->UserContext);
      std::promise<FileContext> result;
      FileContext data = context->Do(
          [=] { return context->GetFileContext(ToUnixPath(filename)); });
      ToFileInfo(FileSystemContext::GetGenericItem(data), file_info);
      *file_context = new FileContext{std::move(data)};
      return STATUS_SUCCESS;
    } catch (const CloudException& e) {
      return ToStatus(e);
    } catch (const std::exception&) {
      return STATUS_INVALID_DEVICE_REQUEST;
    }
  }

  static NTSTATUS GetVolumeInfo(FSP_FILE_SYSTEM* fs,
                                FSP_FSCTL_VOLUME_INFO* volume_info) {
    try {
      auto context = reinterpret_cast<FileSystemContext*>(fs->UserContext);

      auto data = context->Do([context] { return context->GetVolumeData(); });
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
      return STATUS_INVALID_DEVICE_REQUEST;
    }
  }

  static VOID Close(FSP_FILE_SYSTEM*, PVOID file_context) {
    delete reinterpret_cast<FileContext*>(file_context);
  }

  static NTSTATUS ReadDirectory(FSP_FILE_SYSTEM* fs, PVOID file_context_ptr,
                                PWSTR pattern, PWSTR marker, PVOID buffer,
                                ULONG buffer_length, PULONG bytes_transferred) {
    auto file_context = reinterpret_cast<FileContext*>(file_context_ptr);
    auto context = reinterpret_cast<FileSystemContext*>(fs->UserContext);
    auto hint = FspFileSystemGetOperationContext()->Request->Hint;
    context->RunOnEventLoop([=, bytes_transferred =
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
                     context->ReadDirectory(*file_context)) {
          for (auto& item : page_data) {
            data.emplace_back(std::move(item));
          }
        }
        NTSTATUS result;
        if (!FspFileSystemAcquireDirectoryBuffer(&directory_buffer, true,
                                                 &result)) {
          response.IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
          FspFileSystemSendResponse(fs, &response);
          co_return;
        }
        std::sort(data.begin(), data.end(), [](const auto& d1, const auto& d2) {
          return FileSystemContext::GetGenericItem(d1).name <
                 FileSystemContext::GetGenericItem(d2).name;
        });
        for (const FileContext& d : data) {
          auto item = FileSystemContext::GetGenericItem(d);
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
        response.IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
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
    auto context = static_cast<FileSystemContext*>(fs->UserContext);
    auto file = static_cast<FileContext*>(file_context);
    auto hint = FspFileSystemGetOperationContext()->Request->Hint;
    if (static_cast<int64_t>(offset) >=
        FileSystemContext::GetGenericItem(*file).size.value_or(0)) {
      return STATUS_END_OF_FILE;
    }
    context->RunOnEventLoop([=]() -> Task<> {
      FSP_FSCTL_TRANSACT_RSP response;
      memset(&response, 0, sizeof(response));
      response.Size = sizeof(response);
      response.Kind = FspFsctlTransactReadKind;
      response.Hint = hint;
      response.IoStatus.Information = 0;
      try {
        std::string content = co_await context->Read(
            *file, static_cast<int64_t>(offset), static_cast<int64_t>(length));
        memcpy(buffer, content.c_str(), content.size());
        response.IoStatus.Status = STATUS_SUCCESS;
        response.IoStatus.Information = static_cast<uint32_t>(content.size());
        FspFileSystemSendResponse(fs, &response);
      } catch (const CloudException& e) {
        response.IoStatus.Status = ToStatus(e);
        FspFileSystemSendResponse(fs, &response);
      } catch (const std::exception&) {
        response.IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
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

  FileSystemContext context_;
  std::unique_ptr<FSP_FILE_SYSTEM, FileSystemDeleter> filesystem_;
  std::unique_ptr<FSP_FILE_SYSTEM, FileSystemDispatcherDeleter> dispatcher_;
};

NTSTATUS SvcStart(FSP_SERVICE* service, ULONG argc, PWSTR* argv) {
  try {
    if (argc != 2) {
      return STATUS_INVALID_PARAMETER;
    }
    service->UserContext = new WinFspContext(argv[1]);
    return STATUS_SUCCESS;
  } catch (const FileSystemException& e) {
    std::cerr << e.what() << "\n";
    return e.status();
  }
}

NTSTATUS SvcStop(FSP_SERVICE* service) {
  delete reinterpret_cast<WinFspContext*>(service->UserContext);
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
