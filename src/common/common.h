// Axel '0vercl0k' Souchet - February 19 2020
#pragma once
#ifdef _KERNEL_MODE
#    include <ntifs.h>
#    define DWORD ULONG
#else
#    include <windows.h>
#endif

#define IOCTL_SIC_INIT_CONTEXT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_SIC_ENUM_SHMS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

typedef struct _SIC_OFFSETS
{
    DWORD32 EPROCESSToVadRoot;
    DWORD32 MMVAD_SHORTToVadFlags;
    DWORD32 MMVAD_FLAGSPrivateMemoryBitPosition;
} SIC_OFFSETS, *PSIC_OFFSETS;

typedef struct _SIC_SHARED_MEMORY_OWNER_ENTRY
{
    DWORD32 Pid;
    DWORD64 PEPROCESS;
    DWORD64 StartingVirtualAddress;
    DWORD64 EndingVirtualAddress;
} SIC_SHARED_MEMORY_OWNER_ENTRY;

typedef struct _SIC_SHARED_MEMORY_OWNER_ENTRIES
{
    DWORD64 NumberOwners;
    SIC_SHARED_MEMORY_OWNER_ENTRY Owners[1];
} SIC_SHARED_MEMORY_OWNER_ENTRIES;

typedef struct _SIC_SHARED_MEMORY_ENTRY
{
    DWORD64 PrototypePTE;
    SIC_SHARED_MEMORY_OWNER_ENTRIES OwnerEnties;
} SIC_SHARED_MEMORY_ENTRY;

typedef struct _SIC_SHARED_MEMORY_ENTRIES
{
    DWORD64 NumberSharedMemory;
    SIC_SHARED_MEMORY_ENTRY SharedMemoryEntries[1];
} SIC_SHARED_MEMORY_ENTRIES;

typedef struct _SIC_CONTEXT
{
    SIC_OFFSETS Offsets;
} SIC_CONTEXT, *PSIC_CONTEXT;