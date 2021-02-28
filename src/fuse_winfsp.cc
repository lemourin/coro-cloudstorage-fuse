#include "fuse_winfsp.h"

#include <event2/thread.h>
#include <winfsp/winfsp.h>

#include <future>
#include <iostream>
#include <optional>
#include <string>

#include "filesystem_context.h"

namespace coro::cloudstorage::fuse {

namespace {

const int kAllocationUnit = 1;

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
      return STATUS_OBJECT_NAME_NOT_FOUND;
    default:
      return STATUS_INVALID_PARAMETER;
  }
}

std::pair<std::string, std::string> SplitPath(std::string_view path) {
  auto it = path.find_last_of('/');
  if (it == std::string::npos) {
    throw std::invalid_argument("invalid path");
  }
  return {
      std::string(path.begin(), path.begin() + it),
      std::string(path.begin() + it + 1, path.end()),
  };
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

  struct FuseFileContext {
    FileContext context;
    std::string path;
    std::optional<uint64_t> size;
    void* directory_buffer = nullptr;
  };

  WinFspContext(PWSTR mountpoint)
      : event_base_([] {
          evthread_use_windows_threads();
          return event_base_new();
        }()),
        event_loop_(std::async(std::launch::async,
                               [this] {
                                 try {
                                   FileSystemContext context(event_base_.get());
                                   context_ = &context;
                                   initialized_.set_value();
                                   event_base_dispatch(event_base_.get());
                                 } catch (...) {
                                   initialized_.set_exception(
                                       std::current_exception());
                                 }
                                 context_ = nullptr;
                               })),
        filesystem_([this] {
          initialized_.get_future().get();
          FSP_FILE_SYSTEM* filesystem;
          Check(FspFileSystemCreate(
              const_cast<PWSTR>(L"" FSP_FSCTL_NET_DEVICE_NAME), &volume_params_,
              &operations_, &filesystem));
          filesystem->UserContext = context_;
          return filesystem;
        }()),
        dispatcher_([this, mountpoint] {
          Check(FspFileSystemSetMountPoint(filesystem_.get(), mountpoint));
          Check(FspFileSystemStartDispatcher(filesystem_.get(), 0));
          return filesystem_.get();
        }()) {}

  ~WinFspContext() {
    context_->RunOnEventLoop(
        [this]() -> Task<> { co_return context_->Cancel(); });
    dispatcher_.reset();
    filesystem_.reset();
    context_->RunOnEventLoop(
        [this]() -> Task<> { co_return context_->Quit(); });
    event_loop_.get();
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

  static int64_t ToWindowsTimestamp(time_t unix_timestamp) {
    return 10000000ULL * unix_timestamp + 116444736000000000ULL;
  }

  static void ToFileInfo(GenericItem item, FSP_FSCTL_FILE_INFO* info) {
    info->FileAttributes = item.type == GenericItem::Type::kDirectory
                               ? FILE_ATTRIBUTE_DIRECTORY
                               : FILE_ATTRIBUTE_NORMAL;
    info->FileSize = item.size.value_or(0);
    info->ChangeTime = item.timestamp ? ToWindowsTimestamp(*item.timestamp) : 0;
    info->CreationTime = info->ChangeTime;
    info->LastAccessTime = info->ChangeTime;
    info->LastWriteTime = info->ChangeTime;
    info->IndexNumber = 0;
    info->HardLinks = 0;
    info->ReparseTag = 0;
    info->AllocationSize = item.size ? (*item.size + kAllocationUnit - 1) /
                                           kAllocationUnit * kAllocationUnit
                                     : 0;
  }

  static NTSTATUS Open(FSP_FILE_SYSTEM* fs, PWSTR filename,
                       UINT32 create_options, UINT32 granted_access,
                       PVOID* file_context, FSP_FSCTL_FILE_INFO* file_info) {
    auto context = reinterpret_cast<FileSystemContext*>(fs->UserContext);
    return context->Do([=]() -> Task<NTSTATUS> {
      try {
        FileContext data = co_await context->GetFileContext(
            ToUnixPath(filename), stdx::stop_token());
        ToFileInfo(FileSystemContext::GetGenericItem(data), file_info);
        std::unique_ptr<FuseFileContext> fuse_file_context(new FuseFileContext{
            .context = std::move(data), .path = ToUnixPath(filename)});
        *file_context = fuse_file_context.release();
        co_return STATUS_SUCCESS;
      } catch (const CloudException& e) {
        std::cerr << "ERROR " << e.what() << " " << ToUnixPath(filename)
                  << "\n";
        co_return ToStatus(e);
      } catch (const std::exception& e) {
        std::cerr << "ERROR " << e.what() << "\n";
        co_return STATUS_INVALID_DEVICE_REQUEST;
      }
    });
  }

  static NTSTATUS GetVolumeInfo(FSP_FILE_SYSTEM* fs,
                                FSP_FSCTL_VOLUME_INFO* volume_info) {
    auto context = reinterpret_cast<FileSystemContext*>(fs->UserContext);
    return context->Do([=]() -> Task<NTSTATUS> {
      try {
        auto data = co_await context->GetVolumeData(stdx::stop_token());
        volume_info->FreeSize =
            data.space_total ? *data.space_total - data.space_used : UINT64_MAX;
        volume_info->TotalSize =
            data.space_total ? *data.space_total : UINT64_MAX;
        wcscpy_s(volume_info->VolumeLabel, L"cloudstorage");
        volume_info->VolumeLabelLength =
            static_cast<UINT16>(wcslen(volume_info->VolumeLabel));
        co_return STATUS_SUCCESS;
      } catch (const CloudException& e) {
        std::cerr << "ERROR " << e.what() << "\n";
        co_return ToStatus(e);
      } catch (const std::exception& e) {
        std::cerr << "ERROR " << e.what() << "\n";
        co_return STATUS_INVALID_DEVICE_REQUEST;
      }
    });
  }

  static VOID Close(FSP_FILE_SYSTEM* fs, PVOID file_context) {
    auto context = reinterpret_cast<FileSystemContext*>(fs->UserContext);
    context->RunOnEventLoop(
        [context, file_context = reinterpret_cast<FuseFileContext*>(
                      file_context)]() -> Task<> {
          if (file_context) {
            FspFileSystemDeleteDirectoryBuffer(&file_context->directory_buffer);
            delete file_context;
          }
          co_return;
        });
  }

  static NTSTATUS ReadDirectory(FSP_FILE_SYSTEM* fs, PVOID file_context_ptr,
                                PWSTR pattern, PWSTR marker, PVOID buffer,
                                ULONG buffer_length, PULONG bytes_transferred) {
    auto file_context = reinterpret_cast<FuseFileContext*>(file_context_ptr);
    auto context = reinterpret_cast<FileSystemContext*>(fs->UserContext);
    auto hint = FspFileSystemGetOperationContext()->Request->Hint;
    context->RunOnEventLoop([=, bytes_transferred =
                                    *bytes_transferred]() mutable -> Task<> {
      FSP_FSCTL_TRANSACT_RSP response;
      memset(&response, 0, sizeof(response));
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
        std::vector<FileContext> data;
        FOR_CO_AWAIT(
            std::vector<FileContext> & page_data,
            context->ReadDirectory(file_context->context, stdx::stop_token())) {
          for (auto& item : page_data) {
            data.emplace_back(std::move(item));
          }
        }
        NTSTATUS result;
        if (!FspFileSystemAcquireDirectoryBuffer(
                &file_context->directory_buffer, marker == nullptr, &result)) {
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
          if (marker && filename <= marker) {
            continue;
          }
          memcpy(entry->FileNameBuf, filename.c_str(),
                 filename.length() * sizeof(wchar_t));
          memset(&entry->FileInfo, 0, sizeof(entry->FileInfo));
          ToFileInfo(item, &entry->FileInfo);
          entry->Size =
              FIELD_OFFSET(FSP_FSCTL_DIR_INFO, FileNameBuf) +
              static_cast<UINT16>(filename.length() * sizeof(wchar_t));
          if (!FspFileSystemFillDirectoryBuffer(&file_context->directory_buffer,
                                                entry, &result)) {
            break;
          }
        }
        FspFileSystemReleaseDirectoryBuffer(&file_context->directory_buffer);
        FspFileSystemReadDirectoryBuffer(&file_context->directory_buffer,
                                         marker, buffer, buffer_length,
                                         &bytes_transferred);
        response.IoStatus.Status = STATUS_SUCCESS;
        response.IoStatus.Information = bytes_transferred;
        FspFileSystemSendResponse(fs, &response);
      } catch (const CloudException& e) {
        response.IoStatus.Status = ToStatus(e);
        FspFileSystemSendResponse(fs, &response);
        std::cerr << "ERROR " << e.what() << "\n";
      } catch (const std::exception& e) {
        response.IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        FspFileSystemSendResponse(fs, &response);
        std::cerr << "ERROR " << e.what() << "\n";
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
    auto context = static_cast<FileSystemContext*>(fs->UserContext);
    return context->Do([=]() -> Task<NTSTATUS> {
      try {
        auto [directory_name, file_name] = SplitPath(ToUnixPath(filename));
        FileContext parent = co_await context->GetFileContext(
            directory_name, stdx::stop_token());

        try {
          std::unique_ptr<FuseFileContext> fuse_file_context(
              new FuseFileContext{.context = co_await context->GetFileContext(
                                      ToUnixPath(filename), stdx::stop_token()),
                                  .path = ToUnixPath(filename)});
          *file_context = fuse_file_context.release();
          co_return STATUS_OBJECT_NAME_EXISTS;
        } catch (const CloudException&) {
        }

        if (create_options & FILE_DIRECTORY_FILE) {
          FileContext new_item(co_await context->CreateDirectory(
              parent, file_name, stdx::stop_token()));
          ToFileInfo(FileSystemContext::GetGenericItem(new_item), file_info);
          std::unique_ptr<FuseFileContext> fuse_file_context(
              new FuseFileContext{.context = std::move(new_item),
                                  .path = ToUnixPath(filename)});
          *file_context = fuse_file_context.release();
          co_return STATUS_SUCCESS;
        } else {
          *file_info =
              FSP_FSCTL_FILE_INFO{.FileAttributes = FILE_ATTRIBUTE_NORMAL};
          std::unique_ptr<FuseFileContext> fuse_file_context(
              new FuseFileContext{.path = ToUnixPath(filename), .size = 0});
          *file_context = fuse_file_context.release();
          co_return STATUS_SUCCESS;
        }
      } catch (const CloudException& e) {
        std::cerr << "ERROR " << e.what() << "\n";
        co_return ToStatus(e);
      } catch (const std::exception& e) {
        std::cerr << "ERROR " << e.what() << "\n";
        co_return STATUS_INVALID_DEVICE_REQUEST;
      }
    });
  }

  static NTSTATUS SetFileSize(FSP_FILE_SYSTEM* fs, PVOID file_context,
                              UINT64 new_size, BOOLEAN set_allocation_size,
                              FSP_FSCTL_FILE_INFO* info) {
    auto file = static_cast<FuseFileContext*>(file_context);
    file->size = new_size;
    auto item = FileSystemContext::GetGenericItem(file->context);
    item.size = new_size;
    ToFileInfo(item, info);
    return STATUS_SUCCESS;
  }

  static NTSTATUS Overwrite(FSP_FILE_SYSTEM* fs, PVOID file_context,
                            UINT32 file_attributes,
                            BOOLEAN replace_file_attributes,
                            UINT64 allocation_size,
                            FSP_FSCTL_FILE_INFO* file_info) {
    auto context = static_cast<FileSystemContext*>(fs->UserContext);
    auto file = static_cast<FuseFileContext*>(file_context);
    return context->Do([&]() -> Task<NTSTATUS> {
      try {
        auto [directory_name, file_name] = SplitPath(file->path);
        file->context = co_await context->Flush(
            co_await context->Create(co_await context->GetFileContext(
                                         directory_name, stdx::stop_token()),
                                     file_name, /*size=*/0, stdx::stop_token()),
            stdx::stop_token());
        co_return STATUS_SUCCESS;
      } catch (const CloudException& e) {
        std::cerr << "ERROR " << e.what() << "\n";
        co_return ToStatus(e);
      } catch (const std::exception& e) {
        std::cerr << "ERROR " << e.what() << "\n";
        co_return STATUS_INVALID_DEVICE_REQUEST;
      }
    });
  }

  static NTSTATUS Read(FSP_FILE_SYSTEM* fs, PVOID file_context, PVOID buffer,
                       UINT64 offset, ULONG length, PULONG bytes_transferred) {
    auto context = static_cast<FileSystemContext*>(fs->UserContext);
    auto file = static_cast<FuseFileContext*>(file_context);
    auto hint = FspFileSystemGetOperationContext()->Request->Hint;
    if (static_cast<int64_t>(offset) >=
        FileSystemContext::GetGenericItem(file->context).size.value_or(0)) {
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
            file->context, static_cast<int64_t>(offset),
            static_cast<int64_t>(length), stdx::stop_token());
        memcpy(buffer, content.c_str(), content.size());
        response.IoStatus.Status = STATUS_SUCCESS;
        response.IoStatus.Information = static_cast<uint32_t>(content.size());
        FspFileSystemSendResponse(fs, &response);
      } catch (const CloudException& e) {
        std::cerr << "ERROR " << e.what() << "\n";
        response.IoStatus.Status = ToStatus(e);
        FspFileSystemSendResponse(fs, &response);
      } catch (const std::exception& e) {
        std::cerr << "ERROR " << e.what() << "\n";
        response.IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        FspFileSystemSendResponse(fs, &response);
      }
    });
    return STATUS_PENDING;
  }

  static NTSTATUS Write(FSP_FILE_SYSTEM* fs, PVOID file_context, PVOID pbuffer,
                        UINT64 offset, ULONG length,
                        BOOLEAN write_to_end_of_file, BOOLEAN constrained_io,
                        PULONG bytes_transferred, FSP_FSCTL_FILE_INFO* info) {
    auto context = static_cast<FileSystemContext*>(fs->UserContext);
    auto file = static_cast<FuseFileContext*>(file_context);
    auto hint = FspFileSystemGetOperationContext()->Request->Hint;
    context->RunOnEventLoop([=, buffer = std::string(
                                    reinterpret_cast<const char*>(pbuffer),
                                    length)]() mutable -> Task<> {
      FSP_FSCTL_TRANSACT_RSP response;
      memset(&response, 0, sizeof(response));
      response.Size = sizeof(response);
      response.Kind = FspFsctlTransactWriteKind;
      response.Hint = hint;
      response.IoStatus.Information = 0;
      try {
        if (!file->context.current_write &&
            !file->context.current_streaming_write) {
          auto [directory_name, file_name] = SplitPath(file->path);
          FileContext parent = co_await context->GetFileContext(
              directory_name, stdx::stop_token());
          file->context = co_await context->Create(
              parent, file_name, file->size, stdx::stop_token());
        }

        auto size = file->size.value();
        if (constrained_io) {
          if (offset >= size) {
            response.IoStatus.Status = STATUS_SUCCESS;
            FspFileSystemSendResponse(fs, &response);
            co_return;
          }
          length = std::min<ULONG>(length, static_cast<ULONG>(size - offset));
        }

        co_await context->Write(file->context, buffer, offset,
                                stdx::stop_token());

        auto item = FileSystemContext::GetGenericItem(file->context);
        item.size = size;
        ToFileInfo(item, &response.Rsp.Write.FileInfo);

        response.IoStatus.Status = STATUS_SUCCESS;
        response.IoStatus.Information = length;
        FspFileSystemSendResponse(fs, &response);
      } catch (const CloudException& e) {
        std::cerr << "ERROR " << e.what() << "\n";
        response.IoStatus.Status = ToStatus(e);
        FspFileSystemSendResponse(fs, &response);
      } catch (const std::exception& e) {
        std::cerr << "ERROR " << e.what() << "\n";
        response.IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        FspFileSystemSendResponse(fs, &response);
      }
    });
    return STATUS_PENDING;
  }

  static NTSTATUS Flush(FSP_FILE_SYSTEM* fs, PVOID file_context,
                        FSP_FSCTL_FILE_INFO* info) {
    auto file = static_cast<FuseFileContext*>(file_context);
    auto item = FileSystemContext::GetGenericItem(file->context);
    item.size = file->size.value_or(item.size.value_or(0));
    ToFileInfo(item, info);
    return STATUS_SUCCESS;
  }

  static NTSTATUS GetFileInfo(FSP_FILE_SYSTEM* fs, PVOID file_context,
                              FSP_FSCTL_FILE_INFO* info) {
    auto file = static_cast<FuseFileContext*>(file_context);
    auto item = FileSystemContext::GetGenericItem(file->context);
    item.size = file->size.value_or(item.size.value_or(0));
    ToFileInfo(item, info);
    return STATUS_SUCCESS;
  }

  static VOID Cleanup(FSP_FILE_SYSTEM* fs, PVOID file_context, PWSTR file_name,
                      ULONG flags) {
    auto context = static_cast<FileSystemContext*>(fs->UserContext);
    auto file = static_cast<FuseFileContext*>(file_context);
    if (!file) {
      return;
    }
    if (flags & FspCleanupDelete) {
      context->Do([=]() -> Task<NTSTATUS> {
        try {
          co_await context->Remove(file->context, stdx::stop_token());
          co_return STATUS_SUCCESS;
        } catch (const std::exception& e) {
          std::cerr << "ERROR " << e.what() << "\n";
          co_return STATUS_INVALID_DEVICE_REQUEST;
        }
      });
    }
    if (file->context.current_write || file->context.current_streaming_write) {
      context->Do([=]() -> Task<NTSTATUS> {
        try {
          if (!file->context.current_write &&
              !file->context.current_streaming_write) {
            auto [directory_name, file_name] = SplitPath(file->path);
            FileContext parent = co_await context->GetFileContext(
                directory_name, stdx::stop_token());
            file->context = co_await context->Create(
                parent, file_name, file->size, stdx::stop_token());
          }
          co_await context->Flush(file->context, stdx::stop_token());
          co_return STATUS_SUCCESS;
        } catch (const std::exception& e) {
          std::cerr << "ERROR " << e.what() << "\n";
          co_return STATUS_INVALID_DEVICE_REQUEST;
        }
      });
    }
  }

  static NTSTATUS CanDelete(FSP_FILE_SYSTEM* fs, PVOID file_context,
                            PWSTR file_name) {
    return STATUS_SUCCESS;
  }

  static NTSTATUS Rename(FSP_FILE_SYSTEM* fs, PVOID file_context,
                         PWSTR file_name, PWSTR new_file_name,
                         BOOLEAN replace_if_exists) {
    auto context = static_cast<FileSystemContext*>(fs->UserContext);
    return context->Do([=]() -> Task<NTSTATUS> {
      try {
        const auto& [source_directory_name, source_file_name] =
            SplitPath(ToUnixPath(file_name));
        const auto& [destination_directory_name, destination_file_name] =
            SplitPath(ToUnixPath(new_file_name));

        auto source_item = reinterpret_cast<FuseFileContext*>(file_context);
        FileContext new_item = {.item = source_item->context.item};
        if (source_file_name != destination_file_name) {
          new_item = co_await context->Rename(
              source_item->context, destination_file_name, stdx::stop_token());
        }
        if (source_directory_name != destination_directory_name) {
          source_item->context = co_await context->Move(
              new_item,
              co_await context->GetFileContext(destination_directory_name,
                                               stdx::stop_token()),
              stdx::stop_token());
        }

        co_return STATUS_SUCCESS;
      } catch (const CloudException& e) {
        std::cerr << "ERROR " << e.what() << "\n";
        co_return ToStatus(e);
      } catch (const std::exception& e) {
        std::cerr << "ERROR " << e.what() << "\n";
        co_return STATUS_INVALID_DEVICE_REQUEST;
      }
    });
  }

  struct EventBaseDeleter {
    void operator()(event_base* event_base) const {
      event_base_free(event_base);
    }
  };

  FSP_FSCTL_VOLUME_PARAMS volume_params_ = {.SectorSize = kAllocationUnit,
                                            .SectorsPerAllocationUnit = 1,
                                            .MaxComponentLength = MAX_PATH,
                                            .VolumeSerialNumber = 1,
                                            .FileInfoTimeout = 1000,
                                            .CaseSensitiveSearch = 1,
                                            .CasePreservedNames = 1,
                                            .UnicodeOnDisk = 1,
                                            .ReadOnlyVolume = 0,
                                            .FlushAndPurgeOnCleanup = 1,
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
                                           .Write = Write,
                                           .Flush = Flush,
                                           .GetFileInfo = GetFileInfo,
                                           .SetBasicInfo = nullptr,
                                           .SetFileSize = SetFileSize,
                                           .CanDelete = CanDelete,
                                           .Rename = Rename,
                                           .GetSecurity = nullptr,
                                           .SetSecurity = nullptr,
                                           .ReadDirectory = ReadDirectory};

  std::unique_ptr<event_base, EventBaseDeleter> event_base_;
  std::promise<void> initialized_;
  FileSystemContext* context_ = nullptr;
  std::future<void> event_loop_;
  std::unique_ptr<FSP_FILE_SYSTEM, FileSystemDeleter> filesystem_;
  std::unique_ptr<FSP_FILE_SYSTEM, FileSystemDispatcherDeleter> dispatcher_;
};

}  // namespace

NTSTATUS SvcStart(FSP_SERVICE* service, ULONG argc, PWSTR* argv) {
  try {
    if (argc > 2) {
      return STATUS_INVALID_PARAMETER;
    }
    service->UserContext =
        new WinFspContext(argc == 2 ? argv[1] : const_cast<wchar_t*>(L"X:"));
    return STATUS_SUCCESS;
  } catch (const FileSystemException& e) {
    FspServiceSetExitCode(service, e.status());
    return e.status();
  } catch (const std::exception&) {
    FspServiceSetExitCode(service, STATUS_INVALID_DEVICE_REQUEST);
    return STATUS_INVALID_DEVICE_REQUEST;
  }
}

NTSTATUS SvcStop(FSP_SERVICE* service) {
  delete reinterpret_cast<WinFspContext*>(service->UserContext);
  return STATUS_SUCCESS;
}

}  // namespace coro::cloudstorage::fuse
