#include <pch.h>

#include "main.h"

#include "utils/common.h"
#include "rmsdk.h"

bool g_is_need_stop = false;

int main() {
  AllocConsole();

  (void)freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
  (void)freopen_s((FILE**)stderr, "CONOUT$", "w", stderr);

  HWND h_console = GetConsoleWindow();

  SetForegroundWindow(h_console);

  ShowWindow(h_console, SW_RESTORE);
  ShowWindow(h_console, SW_SHOW);

  LOG("waiting sdk load...");

  if (!rmsdk_wait_init()) {
    LOG("sdk failed to load!");
    return 1;
  }

  LOG("sdk loaded");

  while (!g_is_need_stop) Sleep(1);

  LOG("application stopped!");

  return 0;
}