#include <csignal>
#include <future>
#include <iostream>
#include <sstream>

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

template <typename F>
auto AtScopeExit(F func) {
  struct Guard {
    explicit Guard(F func) : func(std::move(func)) {}
    ~Guard() { func(); }
    Guard(const Guard&) = delete;
    Guard(Guard&&) = delete;

    F func;
  };
  return Guard(std::move(func));
}

#ifdef WIN32

#include "fuse_winfsp.h"

#define kAppId "cloudstorage-fuse"

constexpr int kIconResourceId = 1;
constexpr UINT kIconMessageId = WM_APP + 1;

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
          FspServiceStop(data->service);
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

void Check(NTSTATUS status, const char* func) {
  if (status != STATUS_SUCCESS) {
    std::stringstream error;
    error << "Fatal error in " << func << " (0x" << std::hex << status << ").";
    MessageBox(nullptr, error.str().c_str(), nullptr, MB_OK | MB_ICONERROR);
    throw std::runtime_error(func);
  }
}

template <typename T>
void Check(const T& p, const char* func) {
  if (!p) {
    Check(GetLastError(), func);
  }
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
        Check(mutex, "OpenMutex");
      }
    } else {
      NOTIFYICONDATA data = {.cbSize = sizeof(NOTIFYICONDATA),
                             .hWnd = FindWindow(kAppId, kAppId),
                             .uFlags = NIF_INFO,
                             .szInfo = kAppId " already running",
                             .szInfoTitle = kAppId};
      Check(Shell_NotifyIcon(NIM_MODIFY, &data), "Shell_NotifyIcon");
      return STATUS_SUCCESS;
    }

    Check(FspLoad(nullptr), "FspLoad");

    auto service = Create<FspServiceDelete>([] {
      FSP_SERVICE* service;
      Check(FspServiceCreate(const_cast<wchar_t*>(L"coro-cloudstorage-fuse"),
                             SvcStart, coro::cloudstorage::fuse::SvcStop,
                             nullptr, &service),
            "FspServiceCreate");
      FspServiceAllowConsoleMode(service);
      return service;
    }());

    WNDCLASS wc = {.lpfnWndProc = WindowProc,
                   .hInstance = instance,
                   .lpszClassName = kAppId};
    RegisterClass(&wc);
    auto unregister_class_guard =
        AtScopeExit([&] { UnregisterClass(kAppId, instance); });

    auto hwnd = Create<DestroyWindow>(CreateWindowEx(
        0, kAppId, kAppId, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
        CW_USEDEFAULT, CW_USEDEFAULT, nullptr, nullptr, instance, nullptr));
    Check(hwnd, "CreateWindowEx");
    WindowData window_data{.service = service.get()};
    SetWindowLongPtr(hwnd.get(), GWLP_USERDATA,
                     reinterpret_cast<LONG_PTR>(&window_data));
    service->UserContext = &window_data;

    auto service_thread =
        std::async(std::launch::async, FspServiceLoop, service.get());
    Check(window_data.initialized.get_future().get(), "SvcStart");

    auto icon = Create<DestroyIcon>(
        LoadIcon(instance, MAKEINTRESOURCE(kIconResourceId)));
    Check(icon, "LoadIcon");

    NOTIFYICONDATA data = {
        .cbSize = sizeof(NOTIFYICONDATA),
        .hWnd = hwnd.get(),
        .uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE | NIF_INFO,
        .uCallbackMessage = kIconMessageId,
        .hIcon = icon.get(),
        .szTip = kAppId,
        .szInfo = kAppId " started",
        .szInfoTitle = kAppId};
    Check(Shell_NotifyIcon(NIM_ADD, &data), "Shell_NotifyIcon");
    auto delete_notify_icon_guard =
        AtScopeExit([&] { Shell_NotifyIcon(NIM_DELETE, &data); });

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }
    return service_thread.get();
  } catch (const std::exception&) {
    return EXIT_FAILURE;
  }
}
#else
int main() {
  signal(SIGPIPE, SIG_IGN);
  return 0;
}
#endif