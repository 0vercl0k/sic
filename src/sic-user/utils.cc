// Axel '0vercl0k' Souchet - October 6 2020
#include "utils.h"
#include <memory>
#include <windows.h>

#pragma comment(lib, "ntdll")

//
// Thanks to ProcessHacker's native library:
// https://github.com/processhacker/phnt
//

enum class SYSTEM_INFORMATION_CLASS : uint32_t {
  SystemProcessInformation = 5, // q: SYSTEM_PROCESS_INFORMATION
};

struct UNICODE_STRING {
  uint16_t Length;
  uint16_t MaximumLength;
  char16_t *Buffer;
};

using PUNICODE_STRING = UNICODE_STRING *;

struct SYSTEM_PROCESS_INFORMATION {
  ULONG NextEntryOffset;
  ULONG NumberOfThreads;
  LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
  ULONG HardFaultCount;                // since WIN7
  ULONG NumberOfThreadsHighWatermark;  // since WIN7
  ULONGLONG CycleTime;                 // since WIN7
  LARGE_INTEGER CreateTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER KernelTime;
  UNICODE_STRING ImageName;
  UINT32 BasePriority;
  uintptr_t UniqueProcessId;
};

using PSYSTEM_PROCESS_INFORMATION = SYSTEM_PROCESS_INFORMATION *;

extern "C" NTSYSCALLAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    const SYSTEM_INFORMATION_CLASS SystemInformationClass,
    const PVOID SystemInformation, const uint32_t SystemInformationLength,
    uint32_t *ReturnLength);

bool NT_SUCCESS(const NTSTATUS Status) { return Status >= 0; }

std::unordered_map<uintptr_t, std::u16string> GetProcessList() {
  const uint32_t MaxAttempts = 10;
  std::unordered_map<uintptr_t, std::u16string> Processes;

  //
  // Try out to get a process list in a maximum number of attempts.
  // We do this because we can encounter racy behavior where the world
  // changes in between the two ZwQuerySystemInformation.. sigh.
  //

  std::unique_ptr<uint8_t[]> LocalProcessList;
  uint32_t BiggestLength = 0;
  for (uint32_t Attempt = 0; Attempt < MaxAttempts; Attempt++) {
    uint32_t ReturnLength = 0;

    //
    // How much space do we need?
    //

    ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation,
                             nullptr, 0, &ReturnLength);

    //
    // Allocate memory to receive the process list.
    //

    if (ReturnLength > BiggestLength) {
      BiggestLength = ReturnLength;
    }

    LocalProcessList = std::make_unique<uint8_t[]>(BiggestLength);

    //
    // Get a list of the processes running on the system.
    //

    if (const NTSTATUS Status = ZwQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS::SystemProcessInformation,
            LocalProcessList.get(), BiggestLength, &ReturnLength);
        !NT_SUCCESS(Status)) {
      printf("Second ZwQuerySystemInformation failed with %lx\n", Status);
      continue;
    }

    break;
  }

  //
  // If we don't have a buffer allocated we failed, so just bail.
  //

  if (!LocalProcessList) {
    return Processes;
  }

  //
  // Walk the buffer and populate the list of processes.
  //

  auto ProcessList = PSYSTEM_PROCESS_INFORMATION(LocalProcessList.get());
  while (ProcessList->NextEntryOffset) {

    //
    // Check if we have a valid pointer for the name.
    //

    const auto ImageName = ProcessList->ImageName.Buffer;
    if (ImageName) {
      Processes.emplace(ProcessList->UniqueProcessId, ImageName);
    }

    //
    // Move to the next entry.
    //

    ProcessList = PSYSTEM_PROCESS_INFORMATION(uintptr_t(ProcessList) +
                                              ProcessList->NextEntryOffset);
  }

  //
  // We're done, yay!
  //

  return Processes;
}
