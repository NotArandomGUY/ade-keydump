#include <pch.h>
#include <winternl.h>

#include "utils/common.h"
#include "utils/winnt.h"

using namespace std;

LONG NTAPI exception_handler(PEXCEPTION_POINTERS exp) {
  PEXCEPTION_RECORD record = exp->ExceptionRecord;
  PCONTEXT context = exp->ContextRecord;

  switch (record->ExceptionCode) {
  case EXCEPTION_ACCESS_VIOLATION: {
    ULONG operation = (ULONG)record->ExceptionInformation[0];
    LPVOID addr = (LPVOID)record->ExceptionInformation[1];

    char op = '?';
    switch (operation) {
    case 0: op = 'R'; break;
    case 1: op = 'W'; break;
    case 8: op = 'E'; break;
    default: op = operation + '0'; break;
    }

    suspend_all_thread();
    #ifdef _X86_
    LOG("I'm dead: %d, @%08lX-[%c]>%08lX", GetCurrentThreadId(), context->Eip, op, addr);
    #else
    LOG("I'm dead: %d, @%016llX-[%c]>%016llX", GetCurrentThreadId(), context->Rip, op, addr);
    #endif
    SuspendThread(GetCurrentThread());
    break;
  }
  }

  return EXCEPTION_CONTINUE_SEARCH;
}

string execute_command(wstring exePath, wstring args) {
  SECURITY_ATTRIBUTES sa;
  sa.nLength = sizeof(SECURITY_ATTRIBUTES);
  sa.lpSecurityDescriptor = NULL;
  sa.bInheritHandle = TRUE;

  HANDLE hChildStdoutRd, hChildStdoutWr;
  if (!CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &sa, 0)) {
    LOG("Failed to create stdout pipe");
    return "";
  }

  // Ensure the read handle to the stdout pipe is not inherited.
  SetHandleInformation(hChildStdoutRd, HANDLE_FLAG_INHERIT, 0);

  // Create process
  STARTUPINFO si;
  PROCESS_INFORMATION pi;

  SecureZeroMemory(&si, sizeof(STARTUPINFO));
  SecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

  si.cb = sizeof(STARTUPINFO);
  si.hStdOutput = hChildStdoutWr;
  si.dwFlags |= STARTF_USESTDHANDLES;

  wstring cmdLine = L"\"" + exePath + L"\" " + args;

  if (!CreateProcessW(
    exePath.c_str(),
    cmdLine.data(),
    NULL, NULL, TRUE,
    0,
    NULL,
    NULL,
    &si, &pi
  ))
  {
    LOG("Create process error: %d", GetLastError());
    CloseHandle(hChildStdoutWr);
    CloseHandle(hChildStdoutRd);
    return "";
  }

  // Close the write end of the pipe.
  CloseHandle(hChildStdoutWr);

  // Read output from child process's stdout
  const int bufferSize = 4096;
  char buffer[bufferSize];
  string output;

  DWORD bytesRead = 0;
  while (ReadFile(hChildStdoutRd, buffer, bufferSize - 1, &bytesRead, NULL) && bytesRead != 0)
  {
    buffer[bytesRead] = L'\0';
    output += buffer;
  }

  // Close the read end of the pipe.
  CloseHandle(hChildStdoutRd);

  // Wait for the child process to exit.
  WaitForSingleObject(pi.hProcess, INFINITE);

  // Close process and thread handles
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  return output;
}

void suspend_all_thread() {
  DWORD procId = GetCurrentProcessId();
  DWORD threadId = GetCurrentThreadId();

  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, procId);
  if (hSnapshot == INVALID_HANDLE_VALUE) return;

  THREADENTRY32 te{};
  te.dwSize = sizeof(te);
  if (Thread32First(hSnapshot, &te)) {
    do {
      // Suspend all threads EXCEPT this one
      if (te.th32OwnerProcessID != procId || te.th32ThreadID == threadId) continue;

      HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
      if (hThread == NULL) continue;

      SuspendThread(hThread);
      CloseHandle(hThread);
    } while (Thread32Next(hSnapshot, &te));
  }

  CloseHandle(hSnapshot);
}

void resume_all_thread() {
  DWORD procId = GetCurrentProcessId();
  DWORD threadId = GetCurrentThreadId();

  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, procId);
  if (hSnapshot == INVALID_HANDLE_VALUE) return;

  THREADENTRY32 te{};
  te.dwSize = sizeof(te);
  if (Thread32First(hSnapshot, &te)) {
    do {
      // Resume all threads EXCEPT this one
      if (te.th32OwnerProcessID != procId || te.th32ThreadID == threadId) continue;

      HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
      if (hThread == NULL) continue;

      ResumeThread(hThread);
      CloseHandle(hThread);
    } while (Thread32Next(hSnapshot, &te));
  }

  CloseHandle(hSnapshot);
}

void register_exception_handler() {
  SetUnhandledExceptionFilter(exception_handler);
  AddVectoredExceptionHandler(1, exception_handler);
}