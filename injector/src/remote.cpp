#include "remote.h"

#include "utils/common.h"

#include <stdio.h>

namespace remote {
  LPVOID malloc(HANDLE h_process, size_t size) {
    return VirtualAllocEx(h_process, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  }

  BOOL free(HANDLE h_process, LPVOID lp_addr) {
    return VirtualFreeEx(h_process, lp_addr, 0, MEM_RELEASE);
  }

  LPVOID read(HANDLE h_process, LPVOID lp_base_addr, size_t size) {
    LPVOID p_buffer = ::malloc(size);

    if (p_buffer == NULL || !ReadProcessMemory(h_process, lp_base_addr, p_buffer, size, NULL)) {
      ::free(p_buffer);
      return NULL;
    }

    return p_buffer;
  }

  BOOL write(HANDLE h_process, LPVOID lp_base_addr, LPCVOID lp_buf, size_t size) {
    return WriteProcessMemory(h_process, lp_base_addr, lp_buf, size, NULL);
  }

  HANDLE call(HANDLE h_process, LPCSTR lp_module_name, LPCSTR lp_proc_name, LPVOID param, DWORD dw_creation_flags) {
    HMODULE h_module = GetModuleHandleA(lp_module_name);
    if (h_module == NULL) {
      LOG("GetModuleHandleA failed with error %d.", GetLastError());
      return NULL;
    }

    LPVOID p_proc = GetProcAddress(h_module, lp_proc_name);
    if (p_proc == NULL) {
      LOG("GetProcAddress failed with error %d.", GetLastError());
      return NULL;
    }

    HANDLE h_thread = CreateRemoteThread(h_process, NULL, NULL, (LPTHREAD_START_ROUTINE)p_proc, param, dw_creation_flags, NULL);
    if (h_thread == NULL) {
      LOG("CreateRemoteThread failed with error %d.", GetLastError());
      return NULL;
    }

    return h_thread;
  }

  int set_default_dll_directories(HANDLE h_process, DWORD dw_directory_flags) {
    if (h_process == NULL) {
      LOG("h_process == NULL");
      return -1;
    }

    // calling SetDefaultDllDirectories in remote process
    HANDLE h_thread = call(h_process, "kernel32.dll", "SetDefaultDllDirectories", (LPVOID)dw_directory_flags, NULL);
    if (h_thread == NULL) {
      LOG("failed to create remote thread");
      return -2;
    }

    LOG("waiting for remote thread to end...");

    // waiting for remote thread to end
    if (WaitForSingleObject(h_thread, 10000) == WAIT_OBJECT_0) {
      LOG("remote thread ended successfully");
    }

    return 0;
  }

  int add_dll_directory(HANDLE h_process, LPCWSTR lp_new_directory, size_t size) {
    if (h_process == NULL) {
      LOG("h_process == NULL");
      return -1;
    }
    if (size <= 0) size = wcslen(lp_new_directory) * sizeof(WCHAR);

    // allocate memory in remote process
    LPVOID lp_remote_new_directory = malloc(h_process, size);
    if (lp_remote_new_directory == NULL) {
      LOG("failed to allocate memory in target process");
      return -2;
    }

    // write to the memory allocated
    if (!write(h_process, lp_remote_new_directory, lp_new_directory, size)) {
      LOG("failed to write remote process memory");
      free(h_process, lp_remote_new_directory);
      return -3;
    }

    // calling AddDllDirectory in remote process
    HANDLE h_thread = call(h_process, "kernel32.dll", "AddDllDirectory", lp_remote_new_directory, NULL);
    if (h_thread == NULL) {
      LOG("failed to create remote thread");
      free(h_process, lp_remote_new_directory);
      return -4;
    }

    LOG("waiting for remote thread to end...");

    // waiting for remote thread to end
    if (WaitForSingleObject(h_thread, 10000) == WAIT_OBJECT_0) {
      LOG("remote thread ended successfully");
      free(h_process, lp_remote_new_directory);
    }

    return 0;
  }

  int load_library(HANDLE h_process, LPCSTR lp_file_name, size_t size, HANDLE* ph_thread, bool suspend) {
    if (h_process == NULL) {
      LOG("h_process == NULL");
      return -1;
    }

    // allocate memory in the other process
    LPVOID lp_dll_name = malloc(h_process, size);
    if (lp_dll_name == NULL) {
      LOG("failed to allocate memory in target process");
      return -2;
    }

    // write to the memory allocated
    if (!write(h_process, lp_dll_name, lp_file_name, size)) {
      LOG("failed to write remote process memory");
      free(h_process, lp_dll_name);
      return -3;
    }

    // calling LoadLibraryA in the other process
    HANDLE h_thread = call(h_process, "kernel32.dll", "LoadLibraryA", lp_dll_name, CREATE_SUSPENDED);
    if (h_thread == NULL) {
      LOG("failed to create remote thread");
      free(h_process, lp_dll_name);
      return -4;
    }

    *ph_thread = h_thread;

    if (!suspend) {
      ResumeThread(h_thread);

      LOG("waiting for remote thread to end...");

      // waiting for remote thread to end
      if (WaitForSingleObject(h_thread, 10000) == WAIT_OBJECT_0) {
        LOG("remote thread ended successfully");
        free(h_process, lp_dll_name);
      }
    }

    return 0;
  }

  int load_library(HANDLE h_process, LPCWSTR lp_file_name, size_t size, HANDLE* ph_thread, bool suspend) {
    if (h_process == NULL) {
      LOG("h_process == NULL");
      return -1;
    }

    // allocate memory in the other process
    LPVOID lp_dll_name = malloc(h_process, size);
    if (lp_dll_name == NULL) {
      LOG("failed to allocate memory in target process");
      return -2;
    }

    // write to the memory allocated
    if (!write(h_process, lp_dll_name, lp_file_name, size)) {
      LOG("failed to write remote process memory");
      free(h_process, lp_dll_name);
      return -3;
    }

    // calling LoadLibraryW in the other process
    HANDLE h_thread = call(h_process, "kernel32.dll", "LoadLibraryW", lp_dll_name, CREATE_SUSPENDED);
    if (h_thread == NULL) {
      LOG("failed to create remote thread");
      free(h_process, lp_dll_name);
      return -4;
    }

    *ph_thread = h_thread;

    if (!suspend) {
      ResumeThread(h_thread);

      LOG("waiting for remote thread to end...");

      // waiting for remote thread to end
      if (WaitForSingleObject(h_thread, 10000) == WAIT_OBJECT_0) {
        LOG("remote thread ended successfully");
        free(h_process, lp_dll_name);
      }
    }

    return 0;
  }
}