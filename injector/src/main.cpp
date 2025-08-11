#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include "utils/common.h"

#include "remote.h"

#include <windows.h>
#include <TlHelp32.h>
#include <stdlib.h>
#include <io.h>
#include <time.h>
#include <codecvt>
#include <filesystem>
#include <iostream>
#include <string>

using namespace std;

static BOOL is_process_suspended(DWORD dw_pid) {
  BOOL isSuspended = TRUE;
  if (dw_pid == 0) return isSuspended;

  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dw_pid);
  THREADENTRY32 thread;
  ZeroMemory(&thread, sizeof(thread));
  thread.dwSize = sizeof(thread);

  if (Thread32First(hSnapshot, &thread)) {
    do {
      if (thread.th32OwnerProcessID != dw_pid) continue;

      HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread.th32ThreadID);
      if (hThread == NULL) continue;

      isSuspended = SuspendThread(hThread) > 0;
      ResumeThread(hThread);

      if (!isSuspended) break;
    } while (Thread32Next(hSnapshot, &thread));
  }

  CloseHandle(hSnapshot);

  return isSuspended;
}

static int get_processby_pid(DWORD dw_pid, HANDLE* h_process, HANDLE* h_thread) {
  *h_process = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dw_pid);

  return *h_process == NULL ? -1 : 0;
}

static int get_process_by_name(string name, HANDLE* h_process, HANDLE* h_thread) {
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot == INVALID_HANDLE_VALUE) return -1;

  wstring wname = wstring_convert<codecvt_utf8_utf16<wchar_t>>().from_bytes(name);
  DWORD pid = 0;

  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof(pe);

  if (Process32FirstW(hSnapshot, &pe)) {
    do {
      if (!wstring(pe.szExeFile).ends_with(wname) || is_process_suspended(pe.th32ProcessID)) continue;

      pid = pe.th32ProcessID;
      break;
    } while (Process32NextW(hSnapshot, &pe));
  }

  CloseHandle(hSnapshot);

  return pid == 0 ? -1 : get_processby_pid(pid, h_process, h_thread);
}

static int create_process(int argc, char* argv[], HANDLE* h_process, HANDLE* h_thread) {
  TCHAR buffer[MAX_PATH] = { 0 };
  GetModuleFileNameW(NULL, buffer, MAX_PATH);

  wstring exe_dir = wstring(buffer);
  wstring exe_name = wstring(buffer);
  exe_dir = exe_dir.substr(0, exe_dir.find_last_of(L"\\/"));
  exe_name = exe_name.substr(exe_name.find_last_of(L"\\/") + 1);
  exe_name = exe_name.substr(0, exe_name.find_last_of(L"."));

  string args;
  for (int i = 0; i < argc; i++) {
    if (i > 0) args += " ";

    args += '"';
    args += argv[i];
    args += '"';
  }
  wstring cmd_line = wstring_convert<codecvt_utf8_utf16<wchar_t>>().from_bytes(args);

  LOG("executable dir: %s", wstring_convert<codecvt_utf8_utf16<wchar_t>>().to_bytes(exe_dir).c_str());
  LOG("command line: %s", args.c_str());

  STARTUPINFOW si;
  PROCESS_INFORMATION pi;

  SecureZeroMemory(&si, sizeof(STARTUPINFOW));
  SecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

  si.cb = sizeof(STARTUPINFOW);

  BOOL is_success = CreateProcessW(
    (exe_dir + L"\\" + exe_name + L".core.exe").c_str(),
    cmd_line.data(),
    NULL, NULL, TRUE,
    CREATE_SUSPENDED,
    NULL, NULL,
    &si, &pi
  );
  if (!is_success) {
    LOG("create process error: %d", GetLastError());
    return -1;
  }

  *h_process = pi.hProcess;
  *h_thread = pi.hThread;

  return 0;
}

int main(int argc, char* argv[]) {
  AllocConsole();

  (void)freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
  (void)freopen_s((FILE**)stderr, "CONOUT$", "w", stderr);

  HWND h_console = GetConsoleWindow();

  SetForegroundWindow(h_console);

  ShowWindow(h_console, SW_RESTORE);
  ShowWindow(h_console, SW_SHOW);

  LOG("now loading...");

  HANDLE h_process = NULL;
  HANDLE h_thread = NULL;
  HANDLE h_module_thread = NULL;

  if (argc > 2 && string(argv[1]) == "pid") {
    if (get_processby_pid(stoi(argv[2]), &h_process, &h_thread) < 0) return 1;
  }
  else if (argc > 2 && string(argv[1]) == "name") {
    if (get_process_by_name(argv[2], &h_process, &h_thread) < 0) return 1;
  }
  else {
    if (create_process(argc, argv, &h_process, &h_thread) < 0) return 1;
  }

  wstring current_dir = filesystem::current_path();
  wstring module_path = L"rmsdk_unwrapper.dll";

  remote::set_default_dll_directories(
    h_process,
    LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
    LOAD_LIBRARY_SEARCH_USER_DIRS |
    LOAD_LIBRARY_SEARCH_SYSTEM32
  );
  remote::add_dll_directory(h_process, (current_dir + L"\\kdlib").c_str());

  int status = remote::load_library(h_process, module_path.c_str(), module_path.size() * sizeof(wchar_t), &h_module_thread, false);
  if (status != 0) {
    LOG("load module error: %d", status);
    return 1;
  }

  if (h_thread != NULL) {
    Sleep(150);
    ResumeThread(h_thread);
    CloseHandle(h_thread);
  }

  CloseHandle(h_module_thread);

  LOG("module loaded, should be running now...");

  DWORD dw_exit_code;
  while (GetExitCodeProcess(h_process, &dw_exit_code) && dw_exit_code == STILL_ACTIVE) Sleep(1);

  LOG("application stopped!");

  CloseHandle(h_process);
  return 0;
}