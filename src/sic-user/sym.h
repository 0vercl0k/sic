// Axel '0vercl0k' Souchet - February 19 2020
#pragma once
#include <windows.h>

#include <cstdio>
#include <dbghelp.h>

struct ScopedSymInit {
  explicit ScopedSymInit(const DWORD Opts) {
    SymSetOptions(Opts);
    if (!SymInitialize(GetCurrentProcess(), nullptr, false)) {
      printf("SymInitialize failed.\n");
      ExitProcess(0);
    }
  }

  ~ScopedSymInit() {
    //
    // Don't forget to uninitialize the sym subsystem when we're done with it.
    //

    SymCleanup(GetCurrentProcess());
  }
};

bool GetFieldOffset(const DWORD64 Base, const wchar_t *TypeName,
                    const wchar_t *FieldName, DWORD32 *FieldOffset);

bool GetFieldOffsetFromModule(const wchar_t *ModulePath,
                              const wchar_t *TypeName, const wchar_t *FieldName,
                              DWORD32 *FieldOffset);
