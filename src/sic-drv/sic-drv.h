// Axel '0vercl0k' Souchet - February 3 2020
#pragma once
#include <ntifs.h>
#include <ntdef.h>

//
// Include a bunch of undocumented structures that we need to do
// our job.
//

#include "undoc.h"

//
// Some Sic constants / structures.
//

#define SIC_MEMORY_TAG ' ciS'
#define SIC_MEMORY_TAG_AVL_ENTRY 'AciS'
#define SIC_MEMORY_TAG_LIST_ENTRY 'SciS'

#ifdef DBG
#    define DebugPrint(_fmt_, ...) \
        { \
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0xffffffff, (_fmt_), __VA_ARGS__); \
        }
#    ifdef SIC_VERBOSE
#        define DebugPrintVerbose(_fmt_, ...) DebugPrint((_fmt_), __VA_ARGS__)
#    else
#        define DebugPrintVerbose(_fmt_, ...) /* Nuthin. */
#    endif                                    // SIC_VERBOSE
#else
#    define DebugPrint(...)        /* Nuthin. */
#    define DebugPrintVerbose(...) /* Nuthin. */
#endif                             // DBG

typedef struct _SICK_LOOKUP_NODE_OWNERS
{
    LIST_ENTRY List;
    DWORD64 Pid;
    PEPROCESS Process;
    ULONG_PTR StartingVirtualAddress;
    ULONG_PTR EndingVirtualAddress;
} SICK_LOOKUP_NODE_OWNER, *PSICK_LOOKUP_NODE_OWNER;

typedef struct _SIC_LOOKUP_VAD_NODE
{
    struct _MMPTE *FirstPrototypePte;
    LIST_ENTRY Owners;
} SIC_LOOKUP_VAD_NODE, *PSIC_LOOKUP_VAD_NODE;

_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_ typedef NTSTATUS (*SIC_WALK_VAD_ROUTINE)(_In_ const PMMVAD Vad, _Inout_opt_ PVOID Context);

typedef struct _SIC_WALK_VAD_CTX
{
    PRTL_AVL_TABLE LookupTable;
    PEPROCESS Process;
} SIC_WALK_VAD_CTX, *PSIC_WALK_VAD_CTX;

typedef struct _SIC_PROCESS_TO_DEREF
{
    LIST_ENTRY List;
    PEPROCESS Process;
} SIC_PROCESS_TO_DEREF, *PSIC_PROCESS_TO_DEREF;
