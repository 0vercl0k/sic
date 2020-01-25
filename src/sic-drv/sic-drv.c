// Axel '0vercl0k' Souchet - January 25 2020
#include <ntddk.h>

NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
) {
    NTSTATUS Status = STATUS_FAILED_DRIVER_ENTRY;
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    return Status;
}
