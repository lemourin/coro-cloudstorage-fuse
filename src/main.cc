#include <coro/util/raii_utils.h>

#include <csignal>
#include <future>
#include <iostream>
#include <sstream>

using ::coro::util::AtScopeExit;

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

#ifdef WIN32

#include <coro/cloudstorage/fuse/filesystem_context.h>
#include <coro/cloudstorage/fuse/fuse_winfsp.h>
#include <event2/event.h>
#include <event2/thread.h>

#define kAppId "cloudstorage-fuse"

constexpr int kIconResourceId = 1;
constexpr UINT kIconMessageId = WM_APP + 1;

using ::coro::Task;
using ::coro::cloudstorage::fuse::FileSystemContext;

struct DebugStream : std::streambuf {
  int_type overflow(int_type c) override {
    if (c != EOF) {
      TCHAR buf[] = {static_cast<TCHAR>(c), '\0'};
      OutputDebugStringA(buf);
    }
    return c;
  }
};

struct WideDebugStream : std::wstreambuf {
  int_type overflow(int_type c) override {
    if (c != EOF) {
      WCHAR buf[] = {static_cast<WCHAR>(c), '\0'};
      OutputDebugStringW(buf);
    }
    return c;
  }
};

struct WindowData {
  FSP_SERVICE* service;
  FileSystemContext* context;
  coro::util::EventLoop* event_loop;
  coro::Promise<void> quit;
  std::promise<NTSTATUS> initialized;
};

LRESULT WINAPI WindowProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
  if (msg == kIconMessageId) {
    if (lparam == WM_LBUTTONDOWN) {
      ShellExecute(nullptr, "open", "http://localhost:12345", nullptr, nullptr,
                   SW_SHOWNORMAL);
    } else if (lparam == WM_RBUTTONDOWN) {
      if (POINT mouse_position; GetCursorPos(&mouse_position)) {
        HMENU menu = CreatePopupMenu();
        AppendMenu(menu, MF_STRING, 1, "Quit");
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

std::string NtStatusToString(NTSTATUS status) {
  auto ntdll = Create<FreeLibrary>(LoadLibrary("NTDLL.DLL"));
  if (!ntdll) {
    throw std::runtime_error("LoadLibrary error");
  }
  char* message;
  DWORD result = FormatMessage(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_FROM_HMODULE,
      ntdll.get(), status, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      reinterpret_cast<LPTSTR>(&message), 0, nullptr);
  if (result == 0) {
    return "";
  }
  auto guard = AtScopeExit([&] { LocalFree(message); });
  return std::string(message, message + result);
}

void Check(NTSTATUS status, const char* func) {
  if (status != STATUS_SUCCESS) {
    std::stringstream error;
    error << "Fatal error in " << func << " (0x" << std::hex << status << ").";
    if (auto status_string = NtStatusToString(status); !status_string.empty()) {
      error << "\n" << status_string;
    }
    MessageBox(nullptr, error.str().c_str(), nullptr, MB_OK | MB_ICONERROR);
    throw std::runtime_error(func);
  }
}

void CheckSuccess(bool success, const char* func) {
  if (!success) {
    Check(static_cast<NTSTATUS>(GetLastError()), func);
  }
}

template <typename T>
void CheckNotNull(const T& p, const char* func) {
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
          "FspServiceCreate");
    FspServiceAllowConsoleMode(service);
    return service;
  }());

  auto hwnd = Create<DestroyWindow>(CreateWindowEx(
      0, kAppId, kAppId, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
      CW_USEDEFAULT, CW_USEDEFAULT, nullptr, nullptr, instance, nullptr));
  CheckNotNull(hwnd, "CreateWindowEx");
  WindowData window_data{.service = service.get()};
  SetWindowLongPtr(hwnd.get(), GWLP_USERDATA,
                   reinterpret_cast<LONG_PTR>(&window_data));
  service->UserContext = &window_data;

  auto service_thread =
      std::async(std::launch::async, FspServiceLoop, service.get());
  auto scope_guard = AtScopeExit([&] { FspServiceStop(service.get()); });
  Check(window_data.initialized.get_future().get(), "SvcStart");

  auto icon =
      Create<DestroyIcon>(LoadIcon(instance, MAKEINTRESOURCE(kIconResourceId)));
  CheckNotNull(icon, "LoadIcon");

  NOTIFYICONDATA data = {.cbSize = sizeof(NOTIFYICONDATA),
                         .hWnd = hwnd.get(),
                         .uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE | NIF_INFO,
                         .uCallbackMessage = kIconMessageId,
                         .hIcon = icon.get(),
                         .szTip = kAppId,
                         .szInfo = kAppId " started",
                         .szInfoTitle = kAppId};
  CheckSuccess(Shell_NotifyIcon(NIM_ADD, &data), "Shell_NotifyIcon");
  auto delete_notify_icon_guard =
      AtScopeExit([&] { Shell_NotifyIcon(NIM_DELETE, &data); });

  MSG msg;
  while (GetMessage(&msg, nullptr, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
  return service_thread.get();
}

Task<> CoRunWithNoWinFSP(WindowData* data, event_base* event_base) {
  try {
    FileSystemContext context{event_base};
    coro::util::EventLoop loop{event_base};
    data->context = &context;
    data->event_loop = &loop;
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
    evthread_use_windows_threads();
    auto event_loop = Create<event_base_free>(event_base_new());
    coro::Invoke(CoRunWithNoWinFSP(&window_data, event_loop.get()));
    event_base_dispatch(event_loop.get());
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
  CheckNotNull(hwnd, "CreateWindowEx");
  SetWindowLongPtr(hwnd.get(), GWLP_USERDATA,
                   reinterpret_cast<LONG_PTR>(&window_data));

  NETRESOURCE netresource = {
      .dwType = RESOURCETYPE_DISK,
      .lpLocalName = const_cast<char*>("W:"),
      .lpRemoteName = const_cast<char*>("http://localhost:12345")};
  Check(WNetAddConnection3(hwnd.get(), &netresource, /*lpPassword=*/"",
                           /*lpUserName=*/nullptr, /*dwFlags=*/0),
        "WNetAddConnection3");
  auto connection_guard = AtScopeExit(
      [&] { WNetCancelConnection2("W:", /*dwFlags=*/0, /*fForce=*/true); });
  auto icon =
      Create<DestroyIcon>(LoadIcon(instance, MAKEINTRESOURCE(kIconResourceId)));
  CheckNotNull(icon, "LoadIcon");

  NOTIFYICONDATA data = {.cbSize = sizeof(NOTIFYICONDATA),
                         .hWnd = hwnd.get(),
                         .uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE | NIF_INFO,
                         .uCallbackMessage = kIconMessageId,
                         .hIcon = icon.get(),
                         .szTip = kAppId,
                         .szInfo = kAppId " started without WinFSP",
                         .szInfoTitle = kAppId};
  CheckSuccess(Shell_NotifyIcon(NIM_ADD, &data), "Shell_NotifyIcon");
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
    WORD version_requested = MAKEWORD(2, 2);
    WSADATA wsa_data;
    (void)WSAStartup(version_requested, &wsa_data);

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
        CheckNotNull(mutex, "OpenMutex");
      }
    } else {
      NOTIFYICONDATA data = {.cbSize = sizeof(NOTIFYICONDATA),
                             .hWnd = FindWindow(kAppId, kAppId),
                             .uFlags = NIF_INFO,
                             .szInfo = kAppId " already running",
                             .szInfoTitle = kAppId};
      CheckSuccess(Shell_NotifyIcon(NIM_MODIFY, &data), "Shell_NotifyIcon");
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

#include <coro/cloudstorage/fuse/fuse_posix.h>

int main(int argc, char** argv) {
  signal(SIGPIPE, SIG_IGN);

  return coro::cloudstorage::fuse::Run(argc, argv);
}
#endif