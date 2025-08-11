#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#define NOMINMAX
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include <windows.h>
#include <io.h>
#include <Psapi.h>
#include <stdlib.h>
#include <time.h>
#include <TlHelp32.h>

#include <array>
#include <atomic>
#include <codecvt>
#include <filesystem>
#include <functional>
#include <map>
#include <iomanip>
#include <set>
#include <string>
#include <sstream>
#include <thread>

#include <detours.h>