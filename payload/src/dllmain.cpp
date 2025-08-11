#include <pch.h>

#include "main.h"

BOOL APIENTRY DllMain(HMODULE h_module, DWORD ul_reason, LPVOID lp_reserved)
{
  switch (ul_reason)
  {
  case DLL_PROCESS_ATTACH:
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)main, new HMODULE(h_module), 0, NULL);
    break;
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
    break;
  case DLL_PROCESS_DETACH:
    g_is_need_stop = true;
    break;
  }
  return TRUE;
}

