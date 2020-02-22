// Axel '0vercl0k' Souchet - February 19 2020
#pragma once
#include <windows.h>
#ifdef UNICODE
#    define DBGHELP_TRANSLATE_TCHAR
#endif
#include <dbghelp.h>
#include <tchar.h>

#include <cstdio>

struct ScopedSymInit
{
    explicit ScopedSymInit(const DWORD Opts)
    {
        SymSetOptions(Opts);
        if(!SymInitialize(GetCurrentProcess(), nullptr, false))
        {
            _tprintf(_T("SymInitialize failed.\n"));
            ExitProcess(0);
        }
    }

    ~ScopedSymInit()
    {
        //
        // Don't forget to uninitialize the sym subsystem when we're done with it.
        //

        SymCleanup(GetCurrentProcess());
    }
};

BOOL
GetFieldOffset(const DWORD64 Base, const TCHAR* TypeName, const TCHAR* FieldName, DWORD* FieldOffset);

BOOL
GetFieldOffsetFromModule(const TCHAR* ModulePath, const TCHAR* TypeName, const TCHAR* FieldName, DWORD* FieldOffset);
