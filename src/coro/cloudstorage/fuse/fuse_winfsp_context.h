#ifndef CORO_CLOUDSTORAGE_FUSE_FUSE_WINFSP_CONTEXT_H
#define CORO_CLOUDSTORAGE_FUSE_FUSE_WINFSP_CONTEXT_H

#include <winfsp/winfsp.h>

#include <cstddef>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

#include "coro/util/event_loop.h"

namespace coro::cloudstorage::fuse {

class FileSystemProvider;

class FileSystemException : public std::exception {
 public:
  explicit FileSystemException(HRESULT status);

  HRESULT status() const { return status_; }
  const char* what() const noexcept final { return message_.c_str(); }

 private:
  HRESULT status_;
  std::string message_;
};

class WinFspContext {
 public:
  WinFspContext(coro::util::EventLoop* event_loop, FileSystemProvider* context,
                const wchar_t* mountpoint, const wchar_t* prefix);

  WinFspContext(const WinFspContext&) = delete;
  WinFspContext(WinFspContext&&) = delete;
  WinFspContext& operator=(const WinFspContext&) = delete;
  WinFspContext& operator=(WinFspContext&&) = delete;

  ~WinFspContext();

 private:
  struct FileSystemDeleter {
    void operator()(FSP_FILE_SYSTEM* filesystem) const;
  };

  struct FileSystemDispatcherDeleter {
    void operator()(FSP_FILE_SYSTEM* filesystem) const;
  };

  template <typename F>
  void RunOnEventLoop(F func) {
    return event_loop_->RunOnEventLoop(std::move(func));
  }

  template <typename F>
  NTSTATUS Do(F func) {
    return event_loop_->Do(std::move(func));
  }

  static NTSTATUS Open(FSP_FILE_SYSTEM* fs, PWSTR filename,
                       UINT32 create_options, UINT32 granted_access,
                       PVOID* file_context, FSP_FSCTL_FILE_INFO* file_info);

  static NTSTATUS GetVolumeInfo(FSP_FILE_SYSTEM* fs,
                                FSP_FSCTL_VOLUME_INFO* volume_info);

  static VOID Close(FSP_FILE_SYSTEM* fs, PVOID file_context);

  static NTSTATUS ReadDirectory(FSP_FILE_SYSTEM* fs, PVOID file_context_ptr,
                                PWSTR pattern, PWSTR marker_str, PVOID buffer,
                                ULONG buffer_length, PULONG bytes_transferred);

  static NTSTATUS Create(FSP_FILE_SYSTEM* fs, PWSTR filename,
                         UINT32 create_options, UINT32 granted_access,
                         UINT32 file_attributes,
                         PSECURITY_DESCRIPTOR security_descriptor,
                         UINT64 allocation_size, PVOID* file_context,
                         FSP_FSCTL_FILE_INFO* file_info);

  static NTSTATUS SetFileSize(FSP_FILE_SYSTEM* fs, PVOID file_context,
                              UINT64 new_size, BOOLEAN set_allocation_size,
                              FSP_FSCTL_FILE_INFO* info);

  static NTSTATUS Overwrite(FSP_FILE_SYSTEM* fs, PVOID file_context,
                            UINT32 file_attributes,
                            BOOLEAN replace_file_attributes,
                            UINT64 allocation_size,
                            FSP_FSCTL_FILE_INFO* file_info);

  static NTSTATUS Read(FSP_FILE_SYSTEM* fs, PVOID file_context, PVOID buffer,
                       UINT64 offset, ULONG length, PULONG bytes_transferred);

  static NTSTATUS Write(FSP_FILE_SYSTEM* fs, PVOID file_context, PVOID buffer,
                        UINT64 offset, ULONG length,
                        BOOLEAN write_to_end_of_file, BOOLEAN constrained_io,
                        PULONG bytes_transferred, FSP_FSCTL_FILE_INFO* info);

  static NTSTATUS Flush(FSP_FILE_SYSTEM* fs, PVOID file_context,
                        FSP_FSCTL_FILE_INFO* info);

  static NTSTATUS GetFileInfo(FSP_FILE_SYSTEM* fs, PVOID file_context,
                              FSP_FSCTL_FILE_INFO* info);

  static VOID Cleanup(FSP_FILE_SYSTEM* fs, PVOID file_context, PWSTR file_name,
                      ULONG flags);

  static NTSTATUS CanDelete(FSP_FILE_SYSTEM* fs, PVOID file_context,
                            PWSTR file_name);

  static NTSTATUS Rename(FSP_FILE_SYSTEM* fs, PVOID file_context,
                         PWSTR file_name, PWSTR new_file_name,
                         BOOLEAN replace_if_exists);

  FSP_FSCTL_VOLUME_PARAMS volume_params_;
  FSP_FILE_SYSTEM_INTERFACE operations_;
  coro::util::EventLoop* event_loop_;
  FileSystemProvider* context_;
  stdx::stop_source stop_source_;
  std::unique_ptr<FSP_FILE_SYSTEM, FileSystemDeleter> filesystem_;
  std::unique_ptr<FSP_FILE_SYSTEM, FileSystemDispatcherDeleter> dispatcher_;
};

}  // namespace coro::cloudstorage::fuse

#endif  // CORO_CLOUDSTORAGE_FUSE_FUSE_WINFSP_CONTEXT_H