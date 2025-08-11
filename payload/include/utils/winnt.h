#pragma once

#include <pch.h>

extern DWORD adhThreadId;

std::string execute_command(std::wstring exePath, std::wstring args);

void suspend_all_thread();
void resume_all_thread();

void register_exception_handler();