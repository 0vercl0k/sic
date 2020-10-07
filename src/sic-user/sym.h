// Axel '0vercl0k' Souchet - February 19 2020
#pragma once
#include <windows.h>

#include <cstdio>
#include <dbghelp.h>

//
// RAII class to initialize / uninitialize the symbol APIs.
//

struct ScopedSymInit_t {
  explicit ScopedSymInit_t(const DWORD Opts) {
    SymSetOptions(Opts);
    if (!SymInitialize(GetCurrentProcess(), nullptr, false)) {
      printf("SymInitialize failed.\n");
      ExitProcess(0);
    }
  }

  //
  // Rule of three.
  //

  ScopedSymInit_t(const ScopedSymInit_t &) = delete;
  ScopedSymInit_t &operator=(const ScopedSymInit_t &) = delete;
  ~ScopedSymInit_t() {
    //
    // Don't forget to uninitialize the sym subsystem when we're done with it.
    //

    SymCleanup(GetCurrentProcess());
  }
};

//
// Gets the offset of a field of a symbol exported by a module.
//

bool GetFieldOffsetFromModule(const wchar_t *ModulePath,
                              const wchar_t *TypeName, const wchar_t *FieldName,
                              DWORD32 *FieldOffset);
