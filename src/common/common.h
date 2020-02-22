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
    DWORD EPROCESSToVadRoot;
    DWORD MMVAD_SHORTToVadFlags;
    DWORD MMVAD_FLAGSPrivateMemoryBitPosition;
} SIC_OFFSETS, *PSIC_OFFSETS;

typedef struct _SIC_CONTEXT
{
    SIC_OFFSETS Offsets;
} SIC_CONTEXT, *PSIC_CONTEXT;
