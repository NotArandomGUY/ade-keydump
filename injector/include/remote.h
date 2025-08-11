#pragma once

#include <windows.h>

namespace remote {
  LPVOID malloc(HANDLE h_process, size_t size);
  BOOL free(HANDLE h_process, LPVOID lp_addr);
  LPVOID read(HANDLE h_process, LPVOID lp_base_addr, size_t size);
  BOOL write(HANDLE h_process, LPVOID lp_base_addr, LPCVOID lp_buf, size_t size);
  HANDLE call(HANDLE h_process, LPCSTR lp_module_name, LPCSTR lp_proc_name, LPVOID param, DWORD dw_creation_flags);

  int set_default_dll_directories(HANDLE h_process, DWORD dw_directory_flags);
  int add_dll_directory(HANDLE h_process, LPCWSTR lp_new_directory, size_t size = 0);
  int load_library(HANDLE h_process, LPCSTR lp_file_name, size_t size, HANDLE* ph_thread, bool suspend);
  int load_library(HANDLE h_process, LPCWSTR lp_file_name, size_t size, HANDLE* ph_thread, bool suspend);
}