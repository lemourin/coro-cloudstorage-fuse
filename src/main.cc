#ifdef WIN32

#include <future>
#include <iostream>
#include <sstream>

#include "coro/cloudstorage/fuse/filesystem_context.h"
#include "coro/cloudstorage/fuse/fuse_winfsp.h"
#include "coro/util/raii_utils.h"

using ::coro::util::AtScopeExit;

#define kAppId TEXT("cloudstorage-fuse")

constexpr int kIconResourceId = 1;
constexpr UINT kIconMessageId = WM_APP + 1;

using ::coro::Task;
using ::coro::cloudstorage::fuse::FileSystemContext;

#ifdef UNICODE
using tstring = std::wstring;
using tstringstream = std::wstringstream;
#else
using tstring = std::string;
using tstringstream = std::stringstream;
#endif

template <auto FreeFunc>
struct Deleter {
  template <typename T>
  void operator()(T* d) const {
    if (d) {
      FreeFunc(d);
    }
  }
};

template <auto FreeFunc, typename T>
auto Create(T* d) {
  return std::unique_ptr<T, Deleter<FreeFunc>>(d);
}

struct DebugStream : std::streambuf {
  int_type overflow(int_type c) override {
    CHAR buf[] = {static_cast<CHAR>(c), '\0'};
    OutputDebugStringA(buf);
    return c;
  }
};

struct WideDebugStream : std::wstreambuf {
  int_type overflow(int_type c) override {
    WCHAR buf[] = {static_cast<WCHAR>(c), '\0'};
    OutputDebugStringW(buf);
    return c;
  }
};

struct WindowData {
  FSP_SERVICE* service;
  FileSystemContext* context;
  const coro::util::EventLoop* event_loop;
  coro::Promise<void> quit;
  std::promise<NTSTATUS> initialized;
};

LRESULT WINAPI WindowProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
  if (msg == kIconMessageId) {
    if (lparam == WM_LBUTTONDOWN) {
      ShellExecute(nullptr, TEXT("open"), TEXT(CORO_CLOUDSTORAGE_REDIRECT_URI),
                   nullptr, nullptr, SW_SHOWNORMAL);
    } else if (lparam == WM_RBUTTONDOWN) {
      if (POINT mouse_position; GetCursorPos(&mouse_position)) {
        HMENU menu = CreatePopupMenu();
        AppendMenu(menu, MF_STRING, 1, TEXT("Quit"));
        SetForegroundWindow(hwnd);
        int index = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_LEFTBUTTON,
                                   mouse_position.x, mouse_position.y, 0, hwnd,
                                   nullptr);
        PostMessage(hwnd, WM_NULL, 0, 0);
        if (index == 1) {
          WindowData* data = reinterpret_cast<WindowData*>(
              GetWindowLongPtr(hwnd, GWLP_USERDATA));
          if (data->service) {
            FspServiceStop(data->service);
          } else {
            data->event_loop->RunOnEventLoop([&] { data->quit.SetValue(); });
          }
          PostQuitMessage(EXIT_SUCCESS);
        }
      }
    }
  }
  return DefWindowProc(hwnd, msg, wparam, lparam);
}

NTSTATUS SvcStart(FSP_SERVICE* service, ULONG argc, PWSTR* argv) {
  auto window_data = reinterpret_cast<WindowData*>(service->UserContext);
  NTSTATUS status = coro::cloudstorage::fuse::SvcStart(service, argc, argv);
  window_data->initialized.set_value(status);
  return status;
}

tstring NtStatusToString(NTSTATUS status) {
  auto ntdll = Create<FreeLibrary>(LoadLibrary(TEXT("NTDLL.DLL")));
  if (!ntdll) {
    throw std::runtime_error("LoadLibrary error");
  }
  TCHAR* message;
  DWORD result = FormatMessage(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_FROM_HMODULE,
      ntdll.get(), status, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      reinterpret_cast<LPTSTR>(&message), 0, nullptr);
  if (result == 0) {
    return TEXT("");
  }
  auto guard = AtScopeExit([&] { LocalFree(message); });
  return tstring(message, message + result);
}

void Check(NTSTATUS status, const TCHAR* func) {
  if (status != STATUS_SUCCESS) {
    tstringstream error;
    error << TEXT("Fatal error in ") << func << TEXT(" (0x") << std::hex
          << status << TEXT(").");
    if (auto status_string = NtStatusToString(status); !status_string.empty()) {
      error << TEXT("\n") << status_string;
    }
    MessageBox(nullptr, error.str().c_str(), nullptr, MB_OK | MB_ICONERROR);
    throw std::runtime_error("Check error");
  }
}

void CheckSuccess(bool success, const TCHAR* func) {
  if (!success) {
    Check(static_cast<NTSTATUS>(GetLastError()), func);
  }
}

template <typename T>
void CheckNotNull(const T& p, const TCHAR* func) {
  if (!p) {
    Check(static_cast<NTSTATUS>(GetLastError()), func);
  }
}

int MainWithWinFSP(HINSTANCE instance) {
  auto service = Create<FspServiceDelete>([] {
    FSP_SERVICE* service;
    Check(FspServiceCreate(const_cast<wchar_t*>(L"coro-cloudstorage-fuse"),
                           SvcStart, coro::cloudstorage::fuse::SvcStop, nullptr,
                           &service),
          TEXT("FspServiceCreate"));
    FspServiceAllowConsoleMode(service);
    return service;
  }());

  auto hwnd = Create<DestroyWindow>(CreateWindowEx(
      0, kAppId, kAppId, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
      CW_USEDEFAULT, CW_USEDEFAULT, nullptr, nullptr, instance, nullptr));
  CheckNotNull(hwnd, TEXT("CreateWindowEx"));
  WindowData window_data{.service = service.get()};
  SetWindowLongPtr(hwnd.get(), GWLP_USERDATA,
                   reinterpret_cast<LONG_PTR>(&window_data));
  service->UserContext = &window_data;

  auto service_thread = std::async(std::launch::async, [&] {
    coro::util::SetThreadName("service-thread");
    return FspServiceLoop(service.get());
  });
  auto scope_guard = AtScopeExit([&] { FspServiceStop(service.get()); });
  Check(window_data.initialized.get_future().get(), TEXT("SvcStart"));

  auto icon =
      Create<DestroyIcon>(LoadIcon(instance, MAKEINTRESOURCE(kIconResourceId)));
  CheckNotNull(icon, TEXT("LoadIcon"));

  NOTIFYICONDATA data = {.cbSize = sizeof(NOTIFYICONDATA),
                         .hWnd = hwnd.get(),
                         .uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE | NIF_INFO,
                         .uCallbackMessage = kIconMessageId,
                         .hIcon = icon.get(),
                         .szTip = kAppId,
                         .szInfo = kAppId " started",
                         .szInfoTitle = kAppId};
  CheckSuccess(Shell_NotifyIcon(NIM_ADD, &data), TEXT("Shell_NotifyIcon"));
  auto delete_notify_icon_guard =
      AtScopeExit([&] { Shell_NotifyIcon(NIM_DELETE, &data); });

  MSG msg;
  while (GetMessage(&msg, nullptr, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
  return service_thread.get();
}

Task<> CoRunWithNoWinFSP(WindowData* data,
                         const coro::util::EventLoop* event_loop) {
  try {
    FileSystemContext context{event_loop};
    data->context = &context;
    data->event_loop = event_loop;
    data->initialized.set_value(STATUS_SUCCESS);
    co_await data->quit;
    co_await context.Quit();
  } catch (...) {
    data->initialized.set_exception(std::current_exception());
  }
  data->context = nullptr;
  data->event_loop = nullptr;
}

int MainWithNoWinFSP(HINSTANCE instance) {
  WindowData window_data{};
  auto service_thread = std::async(std::launch::async, [&] {
    coro::util::SetThreadName("event-loop");
    coro::util::EventLoop event_loop;
    coro::RunTask(CoRunWithNoWinFSP(&window_data, &event_loop));
    event_loop.EnterLoop(coro::util::EventLoopType::ExitOnEmpty);
    return STATUS_SUCCESS;
  });
  window_data.initialized.get_future().get();
  auto quit_service = AtScopeExit([&] {
    if (window_data.event_loop) {
      window_data.event_loop->RunOnEventLoop(
          [&] { window_data.quit.SetValue(); });
    }
  });

  auto hwnd = Create<DestroyWindow>(CreateWindowEx(
      0, kAppId, kAppId, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
      CW_USEDEFAULT, CW_USEDEFAULT, nullptr, nullptr, instance, nullptr));
  CheckNotNull(hwnd, TEXT("CreateWindowEx"));
  SetWindowLongPtr(hwnd.get(), GWLP_USERDATA,
                   reinterpret_cast<LONG_PTR>(&window_data));

  NETRESOURCE netresource = {
      .dwType = RESOURCETYPE_DISK,
      .lpLocalName = const_cast<LPTSTR>(TEXT("W:")),
      .lpRemoteName = const_cast<LPTSTR>(TEXT(CORO_CLOUDSTORAGE_REDIRECT_URI))};
  Check(WNetAddConnection3(hwnd.get(), &netresource, /*lpPassword=*/TEXT(""),
                           /*lpUserName=*/nullptr, /*dwFlags=*/0),
        TEXT("WNetAddConnection3"));
  auto connection_guard = AtScopeExit([&] {
    WNetCancelConnection2(TEXT("W:"), /*dwFlags=*/0, /*fForce=*/true);
  });
  auto icon =
      Create<DestroyIcon>(LoadIcon(instance, MAKEINTRESOURCE(kIconResourceId)));
  CheckNotNull(icon, TEXT("LoadIcon"));

  NOTIFYICONDATA data = {.cbSize = sizeof(NOTIFYICONDATA),
                         .hWnd = hwnd.get(),
                         .uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE | NIF_INFO,
                         .uCallbackMessage = kIconMessageId,
                         .hIcon = icon.get(),
                         .szTip = kAppId,
                         .szInfo = kAppId " started without WinFSP",
                         .szInfoTitle = kAppId};
  CheckSuccess(Shell_NotifyIcon(NIM_ADD, &data), TEXT("Shell_NotifyIcon"));
  auto delete_notify_icon_guard =
      AtScopeExit([&] { Shell_NotifyIcon(NIM_DELETE, &data); });

  MSG msg;
  while (GetMessage(&msg, nullptr, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
  return service_thread.get();
}

INT WINAPI WinMain(HINSTANCE instance, HINSTANCE prev_instance, PSTR cmd_line,
                   INT cmd_show) {
  try {
    DebugStream debug_stream;
    std::cerr.rdbuf(&debug_stream);
    WideDebugStream wide_debug_stream;
    std::wcerr.rdbuf(&wide_debug_stream);

    HANDLE mutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, kAppId);
    std::unique_ptr<void, Deleter<ReleaseMutex>> mutex_guard;
    if (!mutex) {
      if (GetLastError() == ERROR_FILE_NOT_FOUND) {
        mutex_guard = Create<ReleaseMutex>(CreateMutex(nullptr, 0, kAppId));
      } else {
        CheckNotNull(mutex, TEXT("OpenMutex"));
      }
    } else {
      NOTIFYICONDATA data = {.cbSize = sizeof(NOTIFYICONDATA),
                             .hWnd = FindWindow(kAppId, kAppId),
                             .uFlags = NIF_INFO,
                             .szInfo = kAppId " already running",
                             .szInfoTitle = kAppId};
      CheckSuccess(Shell_NotifyIcon(NIM_MODIFY, &data),
                   TEXT("Shell_NotifyIcon"));
      return STATUS_SUCCESS;
    }

    WNDCLASS wc = {.lpfnWndProc = WindowProc,
                   .hInstance = instance,
                   .lpszClassName = kAppId};
    RegisterClass(&wc);
    auto unregister_class_guard =
        AtScopeExit([&] { UnregisterClass(kAppId, instance); });

    if (FspLoad(nullptr) == STATUS_SUCCESS) {
      return MainWithWinFSP(instance);
    } else {
      return MainWithNoWinFSP(instance);
    }
  } catch (const std::exception&) {
    return EXIT_FAILURE;
  }
}
#else

#include <csignal>

#include "coro/cloudstorage/fuse/fuse_posix.h"

int main(int argc, char** argv) {
  signal(SIGPIPE, SIG_IGN);  // NOLINT

  return coro::cloudstorage::fuse::Run(argc, argv);
}
#endif
