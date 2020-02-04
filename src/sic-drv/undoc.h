// Axel '0vercl0k' Souchet - February 3 2020
#pragma once
#include <ntifs.h>

//
// Thanks to ProcessHacker's native library:
// https://github.com/processhacker/phnt
//

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation, // not implemented
    SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
} SYSTEM_INFORMATION_CLASS;

typedef enum _KTHREAD_STATE
{
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady,
    GateWaitObsolete,
    WaitingForProcessInSwap,
    MaximumThreadState
} KTHREAD_STATE, * PKTHREAD_STATE;

typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    KTHREAD_STATE ThreadState;
    KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
    ULONG HardFaultCount; // since WIN7
    ULONG NumberOfThreadsHighWatermark; // since WIN7
    ULONGLONG CycleTime; // since WIN7
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1]; // SystemProcessInformation
    // SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1]; // SystemExtendedProcessinformation
    // SYSTEM_EXTENDED_THREAD_INFORMATION + SYSTEM_PROCESS_INFORMATION_EXTENSION // SystemFullProcessInformation
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

extern
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

//
// Thanks to ntdiff.github.io / pdbex.
//

typedef struct _MMVAD_SHORT
{
    union
    {
        /* 0x0000 */ struct _RTL_BALANCED_NODE VadNode;
        /* 0x0000 */ struct _MMVAD_SHORT* NextVad;
    } u; /* size: 0x0018 */
    /* 0x0018 */ unsigned long StartingVpn;
    /* 0x001c */ unsigned long EndingVpn;
    /* 0x0020 */ unsigned char StartingVpnHigh;
    /* 0x0021 */ unsigned char EndingVpnHigh;
    /* 0x0022 */ unsigned char CommitChargeHigh;
    /* 0x0023 */ unsigned char SpareNT64VadUChar;
    /* 0x0024 */ long ReferenceCount;
    /* 0x0028 */ /*struct _EX_PUSH_LOCK*/ PVOID PushLock;
    union
    {
        union
        {
            /* 0x0030 */ unsigned long LongFlags;
            // /* 0x0030 */ struct _MMVAD_FLAGS VadFlags;
        } u; /* size: 0x0004 */
    } /* size: 0x0004 */ u2;
    union
    {
        union
        {
            /* 0x0034 */ unsigned long LongFlags1;
            // /* 0x0034 */ struct _MMVAD_FLAGS1 VadFlags1;
        } u; /* size: 0x0004 */
    } /* size: 0x0004 */ u1;
    /* 0x0038 */ struct _MI_VAD_EVENT_BLOCK* EventList;
} MMVAD_SHORT, * PMMVAD_SHORT; /* size: 0x0040 */

typedef struct _MMVAD
{
    /* 0x0000 */ struct _MMVAD_SHORT Core;
    union
    {
        union
        {
            /* 0x0040 */ unsigned long LongFlags2;
            // /* 0x0040 */ struct _MMVAD_FLAGS2 VadFlags2;
        } u; /* size: 0x0004 */
    } /* size: 0x0004 */ u2;
    /* 0x0048 */ struct _SUBSECTION* Subsection;
    /* 0x0050 */ struct _MMPTE* FirstPrototypePte;
    /* 0x0058 */ struct _MMPTE* LastContiguousPte;
    /* 0x0060 */ struct _LIST_ENTRY ViewLinks;
    /* 0x0070 */ struct _EPROCESS* VadsProcess;
    union
    {
        union
        {
            // /* 0x0078 */ struct _MI_VAD_SEQUENTIAL_INFO SequentialVa;
            /* 0x0078 */ struct _MMEXTEND_INFO* ExtendedInfo;
        } u; /* size: 0x0008 */
    } /* size: 0x0008 */ u4;
    /* 0x0080 */ struct _FILE_OBJECT* FileObject;
} MMVAD, * PMMVAD; /* size: 0x0088 */
