#include <csignal>
#include <future>
#include <sstream>

#ifdef WIN32
#include "fuse_winfsp.h"

constexpr int kIconResourceId = 1;
constexpr UINT kIconMessageId = WM_APP + 1;

#endif

template <auto FreeFunc, typename T>
auto Create(T* d) {
  struct Deleter {
    void operator()(T* d) const {
      if (d) {
        FreeFunc(d);
      }
    }
  };
  return std::unique_ptr<T, Deleter>(d);
}

template <typename F>
auto AtScopeExit(F func) {
  struct Guard {
    Guard(F func) : func(std::move(func)) {}
    ~Guard() { func(); }
    Guard(const Guard&) = delete;
    Guard(Guard&&) = delete;

    F func;
  };
  return Guard(std::move(func));
}

#ifdef WIN32

struct WindowData {
  FSP_SERVICE* service;
};

LRESULT WindowProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
  if (msg == kIconMessageId) {
    if (lparam == WM_LBUTTONDOWN) {
      WindowData* data =
          reinterpret_cast<WindowData*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
      FspServiceStop(data->service);
      PostQuitMessage(EXIT_SUCCESS);
    } else if (lparam == WM_RBUTTONDOWN) {
      OutputDebugString("ICON RIGHTCLICKED\n");
    }
  }
  return DefWindowProc(hwnd, msg, wparam, lparam);
}

#endif

#ifdef WIN32
INT WINAPI WinMain(HINSTANCE instance, HINSTANCE prev_instance, PSTR cmd_line,
                   INT cmd_show) {
#else
int main() {
#endif
#ifdef _WIN32
  WORD version_requested = MAKEWORD(2, 2);
  WSADATA wsa_data;

  (void)WSAStartup(version_requested, &wsa_data);
#endif

#ifdef SIGPIPE
  signal(SIGPIPE, SIG_IGN);
#endif

#ifdef WIN32
  if (!NT_SUCCESS(FspLoad(nullptr))) {
    return ERROR_DELAY_LOAD_FAILED;
  }

  FSP_SERVICE* service;
  if (FspServiceCreate(const_cast<wchar_t*>(L"coro-cloudstorage-fuse"),
                       coro::cloudstorage::fuse::SvcStart,
                       coro::cloudstorage::fuse::SvcStop, nullptr,
                       &service) != STATUS_SUCCESS) {
    return EXIT_FAILURE;
  }
  FspServiceAllowConsoleMode(service);
  auto service_free_guard = AtScopeExit([=] { FspServiceDelete(service); });

  const char class_name[] = "cloudstorage-fuse";

  WNDCLASS wc = {.lpfnWndProc = WindowProc,
                 .hInstance = instance,
                 .lpszClassName = class_name};
  RegisterClass(&wc);
  auto unregister_class_guard =
      AtScopeExit([&] { UnregisterClass(class_name, instance); });

  auto hwnd = Create<DestroyWindow>(
      CreateWindowEx(0, class_name, "cloudstorage-fuse", WS_OVERLAPPEDWINDOW,
                     CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                     nullptr, nullptr, instance, nullptr));
  if (hwnd == nullptr) {
    return EXIT_FAILURE;
  }
  WindowData window_data{.service = service};
  SetWindowLongPtr(hwnd.get(), GWLP_USERDATA,
                   reinterpret_cast<LONG_PTR>(&window_data));

  auto icon =
      Create<DestroyIcon>(LoadIcon(instance, MAKEINTRESOURCE(kIconResourceId)));
  if (icon == nullptr) {
    return EXIT_FAILURE;
  }

  NOTIFYICONDATA data = {.cbSize = sizeof(NOTIFYICONDATA),
                         .hWnd = hwnd.get(),
                         .uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE,
                         .uCallbackMessage = kIconMessageId,
                         .hIcon = icon.get(),
                         .szTip = "cloudstorage-fuse"};

  if (!Shell_NotifyIcon(NIM_ADD, &data)) {
    return EXIT_FAILURE;
  }
  auto delete_notify_icon_guard =
      AtScopeExit([&] { Shell_NotifyIcon(NIM_DELETE, &data); });

  auto fuse = std::async(std::launch::async, FspServiceLoop, service);
  MSG msg;
  while (GetMessage(&msg, nullptr, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
  return fuse.get();

#endif
  return EXIT_SUCCESS;
}