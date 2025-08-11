#pragma once

#include <pch.h>

#include "utils/common.h"

#define CALL_ORIGIN(function, ...) HookManager::call(function, __func__, __VA_ARGS__)

class HookManager
{
public:
  template <typename Fn>
  static void install(Fn func, Fn handler)
  {
    enable(func, handler);
    holderMap[reinterpret_cast<void*>(handler)] = reinterpret_cast<void*>(func);
  }
  template <typename Fn>
  static Fn getOrigin(Fn handler, const char* callerName = nullptr, bool silent = false) noexcept
  {
    if (holderMap.count(reinterpret_cast<void*>(handler)) == 0)
    {
      if (!silent) LOG("Origin not found for handler: %s. Maybe racing bug.", callerName);
      return nullptr;
    }
    return reinterpret_cast<Fn>(holderMap[reinterpret_cast<void*>(handler)]);
  }
  template <typename Fn>
  static void detach(Fn handler, bool silent = false) noexcept
  {
    disable(handler, silent);
    holderMap.erase(reinterpret_cast<void*>(handler));
  }
  template <typename RType, typename... Params>
  static RType call(RType(*handler)(Params...), const char* callerName = nullptr, Params... params)
  {
    auto origin = getOrigin(handler, callerName);

    if (origin != nullptr) return origin(params...);

    return RType();
  }
  static void detachAll() noexcept
  {
    for (const auto& [key, value] : holderMap) {
      disable(key, false);
    }

    holderMap.clear();
  }

private:
  inline static std::map<void*, void*> holderMap{};
  template <typename Fn>
  static void disable(Fn handler, bool silent)
  {
    Fn origin = getOrigin(handler, nullptr, silent);

    if (origin == nullptr) return;

    DWORD prot = PAGE_EXECUTE_READWRITE;
    VirtualProtect((LPVOID)origin, 16, prot, &prot);

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)origin, handler);
    DetourTransactionCommit();

    VirtualProtect((LPVOID)origin, 16, prot, &prot);
  }
  template <typename Fn>
  static void enable(Fn& func, Fn handler)
  {
    if (func == nullptr) return;

    disable(handler, true);

    DWORD prot = PAGE_EXECUTE_READWRITE;
    VirtualProtect((LPVOID)func, 16, prot, &prot);

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)func, handler);
    DetourTransactionCommit();

    VirtualProtect((LPVOID)func, 16, prot, &prot);
  }
};