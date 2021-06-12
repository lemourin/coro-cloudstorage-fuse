#ifndef CORO_CLOUDSTORAGE_FUSE_FUSE_WINFSP_CONTEXT_H
#define CORO_CLOUDSTORAGE_FUSE_FUSE_WINFSP_CONTEXT_H

#include <winfsp/winfsp.h>

#include <cstddef>

namespace coro::cloudstorage::fuse {

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
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, nullptr, r, 0, buffer,
                   BUFFER_SIZE, nullptr);
    return buffer;
  }

  HRESULT status_;
  std::string message_;
};

template <typename FileSystemProvider>
class WinFspContext {
 public:
  using FileSystemProviderT = FileSystemProvider;

  WinFspContext(coro::util::EventLoop* event_loop, FileSystemProviderT* context,
                const wchar_t* mountpoint, const wchar_t* prefix)
      : event_loop_(event_loop),
        context_(context),
        filesystem_([&] {
          memcpy(volume_params_.Prefix, prefix,
                 sizeof(wchar_t) * (wcslen(prefix) + 1));
          FSP_FILE_SYSTEM* filesystem;
          Check(FspFileSystemCreate(
              const_cast<PWSTR>(L"" FSP_FSCTL_NET_DEVICE_NAME), &volume_params_,
              &operations_, &filesystem));
          filesystem->UserContext = this;
          return filesystem;
        }()),
        dispatcher_([&] {
          Check(FspFileSystemSetMountPoint(filesystem_.get(),
                                           const_cast<wchar_t*>(mountpoint)));
          Check(FspFileSystemStartDispatcher(filesystem_.get(), 0));
          return filesystem_.get();
        }()) {}

  WinFspContext(const WinFspContext&) = delete;
  WinFspContext(WinFspContext&&) = delete;
  WinFspContext& operator=(const WinFspContext&) = delete;
  WinFspContext& operator=(WinFspContext&&) = delete;

  ~WinFspContext() {
    event_loop_->Do([&] { stop_source_.request_stop(); });
  }

 private:
  using FileContext = typename FileSystemProviderT::ItemContextT;

  static constexpr int kAllocationUnit = 1;

  struct FuseFileContext {
    FileContext context;
    std::string path;
    std::optional<uint64_t> size;
    bool written_to = false;
    void* directory_buffer = nullptr;
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

  static NTSTATUS ToStatus(const CloudException& e) {
    switch (e.type()) {
      case CloudException::Type::kNotFound:
        return STATUS_OBJECT_NAME_NOT_FOUND;
      case CloudException::Type::kUnauthorized:
        return STATUS_ACCESS_DENIED;
      default:
        return STATUS_INVALID_PARAMETER;
    }
  }

  static std::pair<std::string, std::string> SplitPath(std::string_view path) {
    auto it = path.find_last_of('/');
    if (it == std::string::npos) {
      throw std::invalid_argument("invalid path");
    }
    return {
        std::string(path.begin(), path.begin() + it),
        std::string(path.begin() + it + 1, path.end()),
    };
  }

  static void Check(NTSTATUS status) {
    if (status != S_OK) {
      throw FileSystemException(GetLastError());
    }
  }

  static std::string ToUnixPath(const wchar_t* string) {
    char* p;
    Check(FspPosixMapWindowsToPosixPath(const_cast<wchar_t*>(string), &p));
    auto guard = coro::util::AtScopeExit([p] { FspPosixDeletePath(p); });
    return std::string(p);
  }

  static std::wstring ToWindowsPath(const char* path) {
    PWSTR p;
    Check(FspPosixMapPosixToWindowsPath(path, &p));
    auto guard = coro::util::AtScopeExit([p] { FspPosixDeletePath(p); });
    return std::wstring(p);
  }

  template <typename F>
  void RunOnEventLoop(F func) {
    return event_loop_->RunOnEventLoop(std::move(func));
  }

  template <typename F>
  NTSTATUS Do(F func) {
    return event_loop_->Do(std::move(func));
  }

  static int64_t ToWindowsTimestamp(time_t unix_timestamp) {
    return 10000000ULL * unix_timestamp + 116444736000000000ULL;
  }

  static int64_t GetAllocationSize(std::optional<int64_t> size) {
    return size ? (*size + kAllocationUnit - 1) / kAllocationUnit *
                      kAllocationUnit
                : 0;
  }

  static void SetSize(std::optional<int64_t> size, FSP_FSCTL_FILE_INFO* info) {
    info->FileSize = size.value_or(0);
    info->AllocationSize = GetAllocationSize(size);
  }

  static void ToFileInfo(const FileContext& item, FSP_FSCTL_FILE_INFO* info) {
    info->FileAttributes = item.GetType() == FileContext::ItemType::kDirectory
                               ? FILE_ATTRIBUTE_DIRECTORY
                               : FILE_ATTRIBUTE_NORMAL;
    info->ChangeTime =
        item.GetTimestamp() ? ToWindowsTimestamp(*item.GetTimestamp()) : 0;
    info->CreationTime = info->ChangeTime;
    info->LastAccessTime = info->ChangeTime;
    info->LastWriteTime = info->ChangeTime;
    info->IndexNumber = 0;
    info->HardLinks = 0;
    info->ReparseTag = 0;
    SetSize(item.GetSize(), info);
  }

  static NTSTATUS Open(FSP_FILE_SYSTEM* fs, PWSTR filename,
                       UINT32 create_options, UINT32 granted_access,
                       PVOID* file_context, FSP_FSCTL_FILE_INFO* file_info) {
    auto* d = reinterpret_cast<WinFspContext*>(fs->UserContext);
    auto* context = d->context_;
    return d->Do([=]() -> Task<NTSTATUS> {
      try {
        FileContext data = co_await context->GetItemContext(
            ToUnixPath(filename), d->stop_source_.get_token());
        ToFileInfo(data, file_info);
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
    auto* d = reinterpret_cast<WinFspContext*>(fs->UserContext);
    auto* context = d->context_;
    return d->Do([=]() -> Task<NTSTATUS> {
      try {
        auto data =
            co_await context->GetVolumeData(d->stop_source_.get_token());
        volume_info->FreeSize = (data.space_total && data.space_used)
                                    ? *data.space_total - *data.space_used
                                    : UINT64_MAX;
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
    auto* d = reinterpret_cast<WinFspContext*>(fs->UserContext);
    d->RunOnEventLoop([file_context = reinterpret_cast<FuseFileContext*>(
                           file_context)]() -> Task<> {
      if (file_context) {
        FspFileSystemDeleteDirectoryBuffer(&file_context->directory_buffer);
        delete file_context;
      }
      co_return;
    });
  }

  static NTSTATUS ReadDirectory(FSP_FILE_SYSTEM* fs, PVOID file_context_ptr,
                                PWSTR pattern, PWSTR marker_str, PVOID buffer,
                                ULONG buffer_length, PULONG bytes_transferred) {
    auto* d = reinterpret_cast<WinFspContext*>(fs->UserContext);
    auto* context = d->context_;
    auto* file_context = reinterpret_cast<FuseFileContext*>(file_context_ptr);
    auto hint = FspFileSystemGetOperationContext()->Request->Hint;
    auto marker = marker_str ? std::make_optional<std::wstring>(marker_str)
                             : std::nullopt;
    NTSTATUS status;
    if (FspFileSystemAcquireDirectoryBuffer(&file_context->directory_buffer,
                                            !marker, &status)) {
      d->RunOnEventLoop([=, bytes_transferred = *bytes_transferred,
                         marker = std::move(marker)]() mutable -> Task<> {
        FSP_FSCTL_TRANSACT_RSP response;
        memset(&response, 0, sizeof(response));
        response.Size = sizeof(response);
        response.Kind = FspFsctlTransactQueryDirectoryKind;
        response.Hint = hint;
        response.IoStatus.Information = 0;
        try {
          {
            auto guard = coro::util::AtScopeExit([&] {
              FspFileSystemReleaseDirectoryBuffer(
                  &file_context->directory_buffer);
            });
            constexpr auto kBufferSize =
                offsetof(FSP_FSCTL_DIR_INFO, FileNameBuf) +
                MAX_PATH * sizeof(WCHAR);
            union {
              UINT8 data[kBufferSize];
              FSP_FSCTL_DIR_INFO fsctl_dir_info;
            } entry_buffer;
            FSP_FSCTL_DIR_INFO* entry = &entry_buffer.fsctl_dir_info;
            std::vector<FileContext> data;
            FOR_CO_AWAIT(std::vector<FileContext> & page_data,
                         context->ReadDirectory(file_context->context,
                                                d->stop_source_.get_token())) {
              for (auto& item : page_data) {
                data.emplace_back(std::move(item));
              }
            }
            auto [directory_name, file_name] = SplitPath(file_context->path);
            FileContext parent = co_await context->GetItemContext(
                directory_name, d->stop_source_.get_token());
            NTSTATUS result = STATUS_SUCCESS;
            memcpy(entry->FileNameBuf, L".", sizeof(wchar_t));
            memset(&entry->FileInfo, 0, sizeof(entry->FileInfo));
            ToFileInfo(file_context->context, &entry->FileInfo);
            entry->Size = offsetof(FSP_FSCTL_DIR_INFO, FileNameBuf) +
                          static_cast<UINT16>(sizeof(wchar_t));
            FspFileSystemFillDirectoryBuffer(&file_context->directory_buffer,
                                             entry, &result);
            Check(result);
            if (!file_context->context.IsPending()) {
              memcpy(entry->FileNameBuf, L"..", 2 * sizeof(wchar_t));
              memset(&entry->FileInfo, 0, sizeof(entry->FileInfo));
              ToFileInfo(parent, &entry->FileInfo);
              entry->Size = offsetof(FSP_FSCTL_DIR_INFO, FileNameBuf) +
                            static_cast<UINT16>(2 * sizeof(wchar_t));
              FspFileSystemFillDirectoryBuffer(&file_context->directory_buffer,
                                               entry, &result);
              Check(result);
            }
            for (const FileContext& d : data) {
              std::wstring filename = ToWindowsPath(d.GetName().c_str());
              if (filename.length() > MAX_PATH) {
                continue;
              }
              memcpy(entry->FileNameBuf, filename.c_str(),
                     filename.length() * sizeof(wchar_t));
              memset(&entry->FileInfo, 0, sizeof(entry->FileInfo));
              ToFileInfo(d, &entry->FileInfo);
              entry->Size =
                  offsetof(FSP_FSCTL_DIR_INFO, FileNameBuf) +
                  static_cast<UINT16>(filename.length() * sizeof(wchar_t));
              FspFileSystemFillDirectoryBuffer(&file_context->directory_buffer,
                                               entry, &result);
              Check(result);
            }
          }
          FspFileSystemReadDirectoryBuffer(&file_context->directory_buffer,
                                           marker ? marker->data() : nullptr,
                                           buffer, buffer_length,
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
    } else if (status == STATUS_SUCCESS) {
      FspFileSystemReadDirectoryBuffer(&file_context->directory_buffer,
                                       marker_str, buffer, buffer_length,
                                       bytes_transferred);
      return STATUS_SUCCESS;
    } else {
      return status;
    }
  }

  static NTSTATUS Create(FSP_FILE_SYSTEM* fs, PWSTR filename,
                         UINT32 create_options, UINT32 granted_access,
                         UINT32 file_attributes,
                         PSECURITY_DESCRIPTOR security_descriptor,
                         UINT64 allocation_size, PVOID* file_context,
                         FSP_FSCTL_FILE_INFO* file_info) {
    auto* d = reinterpret_cast<WinFspContext*>(fs->UserContext);
    auto* context = d->context_;
    return d->Do([=]() -> Task<NTSTATUS> {
      try {
        auto [directory_name, file_name] = SplitPath(ToUnixPath(filename));
        FileContext parent = co_await context->GetItemContext(
            directory_name, d->stop_source_.get_token());

        try {
          std::unique_ptr<FuseFileContext> fuse_file_context(
              new FuseFileContext{
                  .context = co_await context->GetItemContext(
                      ToUnixPath(filename), d->stop_source_.get_token()),
                  .path = ToUnixPath(filename)});
          *file_context = fuse_file_context.release();
          co_return STATUS_OBJECT_NAME_EXISTS;
        } catch (const CloudException&) {
        }

        if (create_options & FILE_DIRECTORY_FILE) {
          FileContext new_item(co_await context->CreateDirectory(
              parent, file_name, d->stop_source_.get_token()));
          ToFileInfo(new_item, file_info);
          std::unique_ptr<FuseFileContext> fuse_file_context(
              new FuseFileContext{.context = std::move(new_item),
                                  .path = ToUnixPath(filename)});
          *file_context = fuse_file_context.release();
          co_return STATUS_SUCCESS;
        } else {
          auto new_item =
              co_await context->Create(std::move(parent), file_name, /*size=*/0,
                                       d->stop_source_.get_token());
          new_item = co_await context->Flush(std::move(new_item),
                                             d->stop_source_.get_token());
          ToFileInfo(new_item, file_info);
          std::unique_ptr<FuseFileContext> fuse_file_context(
              new FuseFileContext{.context = std::move(new_item),
                                  .path = ToUnixPath(filename)});
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
    auto* file = static_cast<FuseFileContext*>(file_context);
    file->size = new_size;
    ToFileInfo(file->context, info);
    SetSize(new_size, info);
    return STATUS_SUCCESS;
  }

  static NTSTATUS Overwrite(FSP_FILE_SYSTEM* fs, PVOID file_context,
                            UINT32 file_attributes,
                            BOOLEAN replace_file_attributes,
                            UINT64 allocation_size,
                            FSP_FSCTL_FILE_INFO* file_info) {
    auto* d = reinterpret_cast<WinFspContext*>(fs->UserContext);
    auto* context = d->context_;
    auto* file = static_cast<FuseFileContext*>(file_context);
    return d->Do([&]() -> Task<NTSTATUS> {
      try {
        auto [directory_name, file_name] = SplitPath(file->path);
        auto parent = co_await context->GetItemContext(
            directory_name, d->stop_source_.get_token());
        auto new_item =
            co_await context->Create(std::move(parent), file_name, /*size=*/0,
                                     d->stop_source_.get_token());
        file->context = co_await context->Flush(std::move(new_item),
                                                d->stop_source_.get_token());
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
    auto* d = reinterpret_cast<WinFspContext*>(fs->UserContext);
    auto* context = d->context_;
    auto* file = static_cast<FuseFileContext*>(file_context);
    auto hint = FspFileSystemGetOperationContext()->Request->Hint;
    if (static_cast<int64_t>(offset) >= file->context.GetSize().value_or(0)) {
      return STATUS_END_OF_FILE;
    }
    d->RunOnEventLoop([=]() -> Task<> {
      FSP_FSCTL_TRANSACT_RSP response;
      memset(&response, 0, sizeof(response));
      response.Size = sizeof(response);
      response.Kind = FspFsctlTransactReadKind;
      response.Hint = hint;
      response.IoStatus.Information = 0;
      try {
        std::string content = co_await context->Read(
            file->context, static_cast<int64_t>(offset),
            static_cast<int64_t>(length), d->stop_source_.get_token());
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

  static NTSTATUS Write(FSP_FILE_SYSTEM* fs, PVOID file_context, PVOID buffer,
                        UINT64 offset, ULONG length,
                        BOOLEAN write_to_end_of_file, BOOLEAN constrained_io,
                        PULONG bytes_transferred, FSP_FSCTL_FILE_INFO* info) {
    auto* d = reinterpret_cast<WinFspContext*>(fs->UserContext);
    auto* context = d->context_;
    auto file = static_cast<FuseFileContext*>(file_context);
    auto hint = FspFileSystemGetOperationContext()->Request->Hint;
    d->RunOnEventLoop([=]() mutable -> Task<> {
      FSP_FSCTL_TRANSACT_RSP response;
      memset(&response, 0, sizeof(response));
      response.Size = sizeof(response);
      response.Kind = FspFsctlTransactWriteKind;
      response.Hint = hint;
      response.IoStatus.Information = 0;
      try {
        if (!file->written_to) {
          auto [directory_name, file_name] = SplitPath(file->path);
          FileContext parent = co_await context->GetItemContext(
              directory_name, d->stop_source_.get_token());
          file->context = co_await context->Create(
              parent, file_name, file->size, d->stop_source_.get_token());
        }

        if (!file->size) {
          file->size = file->context.GetSize();
        }

        if (write_to_end_of_file) {
          offset = file->size.value();
        }

        if (constrained_io) {
          if (offset >= file->size.value()) {
            response.IoStatus.Status = STATUS_SUCCESS;
            FspFileSystemSendResponse(fs, &response);
            co_return;
          }
          length = std::min<ULONG>(
              length, static_cast<ULONG>(file->size.value() - offset));
        } else {
          if (!file->size || offset + length > *file->size) {
            file->size = offset + length;
          }
        }

        auto size = file->size.value();

        co_await context->Write(
            file->context,
            std::string_view(reinterpret_cast<const char*>(buffer), length),
            offset, d->stop_source_.get_token());
        file->written_to = true;

        ToFileInfo(file->context, &response.Rsp.Write.FileInfo);
        SetSize(size, &response.Rsp.Write.FileInfo);

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
    return GetFileInfo(fs, file_context, info);
  }

  static NTSTATUS GetFileInfo(FSP_FILE_SYSTEM* fs, PVOID file_context,
                              FSP_FSCTL_FILE_INFO* info) {
    auto file = static_cast<FuseFileContext*>(file_context);
    ToFileInfo(file->context, info);
    SetSize(file->size.value_or(file->context.GetSize().value_or(0)), info);
    return STATUS_SUCCESS;
  }

  static VOID Cleanup(FSP_FILE_SYSTEM* fs, PVOID file_context, PWSTR file_name,
                      ULONG flags) {
    auto* d = reinterpret_cast<WinFspContext*>(fs->UserContext);
    auto* context = d->context_;
    auto* file = static_cast<FuseFileContext*>(file_context);
    if (!file) {
      return;
    }
    if (flags & FspCleanupDelete) {
      d->Do([=]() -> Task<NTSTATUS> {
        try {
          co_await context->Remove(file->context, d->stop_source_.get_token());
          co_return STATUS_SUCCESS;
        } catch (const std::exception& e) {
          std::cerr << "ERROR " << e.what() << "\n";
          co_return STATUS_INVALID_DEVICE_REQUEST;
        }
      });
      return;
    }
    if (flags & FspCleanupSetLastWriteTime) {
      d->Do([=]() -> Task<NTSTATUS> {
        try {
          if (!file->written_to) {
            auto [directory_name, file_name] = SplitPath(file->path);
            FileContext parent = co_await context->GetItemContext(
                directory_name, d->stop_source_.get_token());
            file->context = co_await context->Create(
                parent, file_name, file->size, d->stop_source_.get_token());
          }
          co_await context->Flush(file->context, d->stop_source_.get_token());
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
    auto* d = reinterpret_cast<WinFspContext*>(fs->UserContext);
    auto* context = d->context_;
    return d->Do([=]() -> Task<NTSTATUS> {
      try {
        const auto& [source_directory_name, source_file_name] =
            SplitPath(ToUnixPath(file_name));
        const auto& [destination_directory_name, destination_file_name] =
            SplitPath(ToUnixPath(new_file_name));

        auto source_item = reinterpret_cast<FuseFileContext*>(file_context);
        FileContext new_item = FileContext::From(source_item->context);
        if (source_file_name != destination_file_name) {
          new_item = co_await context->Rename(source_item->context,
                                              destination_file_name,
                                              d->stop_source_.get_token());
        }
        if (source_directory_name != destination_directory_name) {
          auto destination = co_await context->GetItemContext(
              destination_directory_name, d->stop_source_.get_token());
          source_item->context = co_await context->Move(
              new_item, std::move(destination), d->stop_source_.get_token());
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
                                            .FileSystemName = L"cloudfs"};
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

  coro::util::EventLoop* event_loop_;
  FileSystemProviderT* context_;
  stdx::stop_source stop_source_;
  std::unique_ptr<FSP_FILE_SYSTEM, FileSystemDeleter> filesystem_;
  std::unique_ptr<FSP_FILE_SYSTEM, FileSystemDispatcherDeleter> dispatcher_;
};

}  // namespace coro::cloudstorage::fuse

#endif  // CORO_CLOUDSTORAGE_FUSE_FUSE_WINFSP_CONTEXT_H