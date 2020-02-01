// Axel '0vercl0k' Souchet - January 25 2020
#include <ntifs.h>

//
// Bunch of useful resources I found useful you also might enjoy:
//   - ProcessHacker's pht project,
//   - Rekall's source-code,
//   - Windows Internals 7th edition
//
// Register the driver:
//   - sc create sic type=kernel binPath=c:\users\over\desktop\sic-drv.sys
//
// Enable DbgPrint:
//    - kd> ed nt!Kd_Default_Mask 8
//

//
// Declare a bunch of functions to satisfy the below pragmas.
//

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD SicDriverUnload;
DRIVER_DISPATCH_PAGED SicDispatchDeviceControl;

//
// Our code doesn't need to be allocated in non-paged memory.
// There is no functions running above APC_LEVEL as a result page faults
// are allowed.
// DriverEntry is in the INIT segment which gets discarded once the driver
// as been initialized.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, SicDriverUnload)
#pragma alloc_text(PAGE, SicDispatchDeviceControl)
#endif

//
// Thanks to ProcessHacker's native library:
// https://github.com/processhacker/phnt
//

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation, // not implemented
    SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
} SYSTEM_INFORMATION_CLASS;

typedef enum _KTHREAD_STATE {
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

typedef struct _SYSTEM_THREAD_INFORMATION {
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
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
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
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

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

#define SIC_MEMORY_TAG ' ciS'

//
// Time to do some work I suppose.
//

_Function_class_(DRIVER_UNLOAD)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID SicDriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
) {
    UNREFERENCED_PARAMETER(DriverObject);
    PAGED_CODE();
}

_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS SicGetProcessList(
    _Out_ PSYSTEM_PROCESS_INFORMATION *ProcessList
) {
    const UINT32 MaxAttempts = 10;
    NTSTATUS Status = STATUS_SUCCESS;

    if(!ARGUMENT_PRESENT(ProcessList)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Initialize the output buffer to NULL.
    //

    *ProcessList = NULL;

    //
    // Try out to get a process list in a maximum number of attempts.
    // We do this because we can encounter racy behavior where the world
    // changes in between the two ZwQuerySystemInformation.. sigh.
    //

    for(UINT32 Attempt = 0; Attempt < MaxAttempts; Attempt++) {
        ULONG ReturnLength = 0;
        PVOID LocalProcessList = NULL;

        //
        // How much space do we need?
        //

        Status = ZwQuerySystemInformation(
            SystemProcessInformation,
            NULL,
            0,
            &ReturnLength
        );

        //
        // Allocate memory to receive the process list.
        //

        LocalProcessList = ExAllocatePoolWithTag(
            PagedPool,
            ReturnLength,
            SIC_MEMORY_TAG
        );

        if(LocalProcessList == NULL) {
            continue;
        }

        //
        // Get a list of the processes running on the system.
        //

        Status = ZwQuerySystemInformation(
            SystemProcessInformation,
            LocalProcessList,
            ReturnLength,
            &ReturnLength
        );

        //
        // If we fail, let's clean up behind ourselves, and give it another try!
        //

        if(!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(
                LocalProcessList,
                SIC_MEMORY_TAG
            );

            LocalProcessList = NULL;
            continue;
        }

        //
        // If we make it here, it means that we have our list and we are done.
        //

        *ProcessList = LocalProcessList;
        break;
    }

    //
    // If we managed to get the list, it's all good otherwise it's a failure.
    //

    return (*ProcessList != NULL) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS SicDude(
) {
    NTSTATUS Status = STATUS_SUCCESS;
    PSYSTEM_PROCESS_INFORMATION ProcessList = NULL;
    PSYSTEM_PROCESS_INFORMATION CurrentProcess = NULL;


    //
    // Get a list of processes.
    //

    Status = SicGetProcessList(&ProcessList);

    if(!NT_SUCCESS(Status)) {
        goto clean;
    }

    //
    // We need to walk each of them and walk through their VAD trees.
    //

    CurrentProcess = ProcessList;
    while(CurrentProcess->NextEntryOffset != 0) {
        PEPROCESS Process = NULL;

        //
        // Display the process name.
        //

        const UNICODE_STRING *ProcessName = &CurrentProcess->ImageName;
        DbgPrint("Process: %wZ\n", ProcessName);

        //
        // Reference the process to not have it die under us.
        //

        Status = PsLookupProcessByProcessId(
            CurrentProcess->UniqueProcessId,
            &Process
        );

        if(!NT_SUCCESS(Status)) {
            goto next;
        }


        //
        // Don't forget to de-reference the EPROCESS object.
        //

        ObDereferenceObject(Process);

        Process = NULL;

        next:

        //
        // We are done with the current process, move to the next.
        //

        CurrentProcess = (PSYSTEM_PROCESS_INFORMATION)(
            (ULONG_PTR)CurrentProcess + CurrentProcess->NextEntryOffset
        );
    }

    clean:

    //
    // Don't forget to clean the process list.
    //

    if(ProcessList != NULL) {
        ExFreePoolWithTag(
            ProcessList,
            SIC_MEMORY_TAG
        );

        ProcessList = NULL;
    }

    return Status;
}

_Function_class_(DRIVER_DISPATCH)
_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS SicDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
) {
    UNREFERENCED_PARAMETER(DeviceObject);
    NTSTATUS Status = STATUS_SUCCESS;
    PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    ULONG IoControlCode = IoStackLocation->Parameters.DeviceIoControl.IoControlCode;

    PAGED_CODE();

    switch(IoControlCode) {
        default: {
            break;
        }
    }

    //
    // We are done with this IRP, so we fill in the IoStatus part.
    //

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;

    //
    // As well as completing it!
    //

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(RegistryPath);

    PAGED_CODE();

    DriverObject->DriverUnload = SicDriverUnload;

    SicDude();

    //
    // Set-up the Unload / I/O callbacks.
    //

    // DriverObject->DriverUnload = SicDriverUnload;
    // DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SicDispatchDeviceControl;
    return STATUS_FAILED_DRIVER_ENTRY;
}
