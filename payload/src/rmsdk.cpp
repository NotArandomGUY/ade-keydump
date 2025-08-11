#include <pch.h>

#include "utils/common.h"
#include "utils/hook-manager.h"
#include "utils/winnt.h"
#include "epub-dumper.h"
#include "rmsdk.h"

using namespace std;
using namespace filesystem;

template <size_t S>
struct MaskedPattern {
  char data[S];
  char mask[S];
};

constexpr auto PATTERN_AES_set_decrypt_key = MaskedPattern{
  "\xE8\x00\x00\x00\x00\x83\x00\x00\x0F\x84\x00\x00\x00\x00\xC3",
  "\xFF\x00\x00\x00\x00\xFF\x00\xFF\xFF\xFF\x00\xFF\xFF\xFF\xFF"
};

static int(__cdecl* s_AES_set_decrypt_key)(char* user_key, int bits, void* key);
static void* (__cdecl* s_zip_open)(char* path, int flags, int* errorp);

static EPubDumper s_dumper;
static string s_last_epub_path;
static set<string> s_processed_id_set;

static void on_open_zip_archive(const string& path) {
  LOG("sdk open zip archive: %s", path.c_str());

  s_last_epub_path = path;
}

static void on_set_decrypt_key(const string& key) {
  if (s_last_epub_path.empty() || s_dumper.is_open()) return;

  string id = s_last_epub_path + key;
  if (s_processed_id_set.contains(id)) return;
  s_processed_id_set.insert(id);

  LOG("sdk set decrypt key: %s", hex_encode(key).c_str());

  int status = s_dumper.open(s_last_epub_path, key);
  if (status < 0) {
    LOG("open epub error: %d", status);
    return;
  }

  s_dumper.dumpAsync();
}

int __cdecl hook_AES_set_decrypt_key(char* user_key, int bits, void* key) {
  int status = CALL_ORIGIN(hook_AES_set_decrypt_key, user_key, bits, key);
  if (status != 0) {
    LOG("sdk set decrypt key error: %d", status);
    return status;
  }

  on_set_decrypt_key(string(user_key, bits >> 3));
  return 0;
}

void* __cdecl hook_zip_open(char* path, int flags, int* errorp) {
  void* za = CALL_ORIGIN(hook_zip_open, path, flags, errorp);
  if (za == nullptr) {
    if (errorp != nullptr) LOG("sdk open zip archive error: %d", *errorp);
    return nullptr;
  }

  on_open_zip_archive(path);
  return za;
}

static void mount_hook() {
  if (s_AES_set_decrypt_key != 0) HookManager::install(s_AES_set_decrypt_key, hook_AES_set_decrypt_key);
  if (s_zip_open != 0) HookManager::install(s_zip_open, hook_zip_open);
}

static void unmount_hook() {
  if (s_AES_set_decrypt_key != 0) HookManager::detach(hook_AES_set_decrypt_key);
  if (s_zip_open != 0) HookManager::detach(hook_zip_open);
}

static bool read_memory(HANDLE h_process, HMODULE h_module, LPBYTE lp_buffer, SIZE_T sz_offset, SIZE_T sz_size) {
  SIZE_T sz_bytes_read = 0;
  return ReadProcessMemory(h_process, (LPCVOID)((UINT_PTR)h_module + sz_offset), lp_buffer + sz_offset, sz_size, &sz_bytes_read);
}

template <size_t S>
static intptr_t match_pattern(HMODULE h_module, LPBYTE lp_buffer, DWORD dw_size, const MaskedPattern<S> pattern) {
  if (h_module == NULL || lp_buffer == NULL || dw_size == 0) return 0;

  for (DWORD dw_pos = 0; dw_pos < dw_size; dw_pos++) {
    bool is_match = true;

    for (size_t i = 0; i < S; i++) {
      size_t pos = dw_pos + i;
      if (pos >= dw_size) goto no_match;

      if ((BYTE)(lp_buffer[pos] & pattern.mask[i]) != (BYTE)pattern.data[i]) {
        is_match = false;
        break;
      }
    }

    if (is_match) return (UINT_PTR)h_module + dw_pos;
  }

no_match:
  return 0;
}

bool rmsdk_wait_init() {
  bool is_loaded = true;

  LPBYTE lp_buffer = NULL;
  DWORD dw_size = 0;
  SIZE_T sz_bytes_read = 0;

  HANDLE h_process = GetCurrentProcess();
  HMODULE h_module = NULL;
  MODULEINFO module_info{};

  intptr_t addr_AES_set_decrypt_key = 0;
  intptr_t offset_AES128StreamCryptorImpl_Init = 0;
  intptr_t addr_zip_open = 0;

  if (h_process == NULL) {
    LOG("get process handle error: %d", GetLastError());
    goto error;
  }

  while (h_module == NULL) {
    h_module = GetModuleHandleA("rmsdk_wrapper.dll");
    if (h_module == NULL) {
      Sleep(1);
      continue;
    }

    if (!GetModuleInformation(h_process, h_module, &module_info, sizeof(module_info))) {
      LOG("get module info error: %d", GetLastError());
      goto error;
    }

    IMAGE_DOS_HEADER* p_dos_header = (IMAGE_DOS_HEADER*)h_module;
    IMAGE_NT_HEADERS* p_nt_headers = (IMAGE_NT_HEADERS*)((intptr_t)h_module + p_dos_header->e_lfanew);

    size_t sec_header_begin = (size_t)p_dos_header->e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + p_nt_headers->FileHeader.SizeOfOptionalHeader;
    size_t sec_header_end = sec_header_begin + (p_nt_headers->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    size_t sec_header_size = sec_header_end - sec_header_begin;
    size_t sec_header_count = sec_header_size / sizeof(IMAGE_SECTION_HEADER);

    dw_size = module_info.SizeOfImage;
    lp_buffer = (LPBYTE)malloc(dw_size);
    if (lp_buffer == NULL) {
      LOG("failed to allocate buffer");
      goto error;
    }
    memset(lp_buffer, 0, dw_size);

    if (!read_memory(h_process, h_module, lp_buffer, sec_header_begin, sec_header_size)) {
      LOG("read section header error: %d", GetLastError());
      goto error;
    }
    auto sec_header_arr = (IMAGE_SECTION_HEADER*)(lp_buffer + sec_header_begin);

    for (size_t i = 0; i < sec_header_count; i++) {
      IMAGE_SECTION_HEADER& section = sec_header_arr[i];

      if ((section.Characteristics & IMAGE_SCN_CNT_CODE) && !read_memory(h_process, h_module, lp_buffer, section.VirtualAddress, section.Misc.VirtualSize)) {
        LOG("read code section error: %d", GetLastError());
        goto error;
      }
    }

    addr_AES_set_decrypt_key = match_pattern(h_module, lp_buffer, dw_size, PATTERN_AES_set_decrypt_key);
    addr_zip_open = (intptr_t)GetProcAddress(h_module, "zip_open");

    LOG("sdk fn (%08lX/%08lX)", addr_AES_set_decrypt_key, addr_zip_open);
  }

  suspend_all_thread();
  register_exception_handler();

  s_AES_set_decrypt_key = (decltype(s_AES_set_decrypt_key))addr_AES_set_decrypt_key;
  s_zip_open = (decltype(s_zip_open))addr_zip_open;

  mount_hook();
  resume_all_thread();

cleanup:
  if (lp_buffer != NULL) {
    free(lp_buffer);
    lp_buffer = NULL;
  }

  return is_loaded;

error:
  unmount_hook();
  is_loaded = false;
  goto cleanup;
}