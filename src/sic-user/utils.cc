// Axel '0vercl0k' Souchet - October 6 2020
#include "utils.h"
#include "sym.h"
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <memory>
#include <windows.h>

namespace fs = std::filesystem;

#pragma comment(lib, "ntdll")

#if defined(__i386__) || defined(_M_IX86)
#define SIC_ARCH "x86"
#elif defined(__amd64__) || defined(_M_X64)
#define SIC_ARCH "x64"
#else
#error Platform not supported.
#endif

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
  wchar_t *Buffer;
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

std::unordered_map<uintptr_t, std::string> GetProcessList() {
  const uint32_t MaxAttempts = 10;
  std::unordered_map<uintptr_t, std::string> Processes;

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

    const auto ImageNameW = ProcessList->ImageName.Buffer;
    if (ImageNameW) {

      //
      // Convert the wide string into a string; it makes the life of the callers
      // easier.
      //

      const uint16_t ImageNameWLength = ProcessList->ImageName.Length / 2;
      std::string ImageNameA(ImageNameWLength, '\0');
      WideCharToMultiByte(CP_ACP, 0, ImageNameW, ImageNameWLength,
                          ImageNameA.data(), int(ImageNameA.length()), 0, 0);

      //
      // Also, lower case the string as it'll make matching better.
      //

      std::transform(ImageNameA.begin(), ImageNameA.end(), ImageNameA.begin(),
                     [](const char C) { return char(std::tolower(C)); });

      //
      // Finally move the string in the vector.
      //

      Processes.emplace(ProcessList->UniqueProcessId, ImageNameA);
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

bool GetOffsets(SIC_OFFSETS &SicOffsets) {

  //
  // Ensure that we both have dbghelp.dll and symsrv.dll in the current
  // directory otherwise things don't work. cf
  // https://docs.microsoft.com/en-us/windows/win32/debug/using-symsrv
  // "Installation"
  //

  char ExePathBuffer[MAX_PATH];
  if (!GetModuleFileNameA(nullptr, &ExePathBuffer[0], sizeof(ExePathBuffer))) {
    printf("GetModuleFileNameA failed.\n");
    return false;
  }

  //
  // Let's check if the two dlls exist in the same path as the application.
  //

  const fs::path ExePath(ExePathBuffer);
  const fs::path ParentDir(ExePath.parent_path());
  if (!fs::exists(ParentDir / "dbghelp.dll") ||
      !fs::exists(ParentDir / "symsrv.dll")) {

    //
    // Apparently they don't. Be nice and try to find them by ourselves.
    //

    const fs::path DefaultDbghelpLocation(
        R"(c:\program Files (x86)\windows kits\10\debuggers\)" SIC_ARCH
        R"(\dbghelp.dll)");
    const fs::path DefaultSymsrvLocation(
        R"(c:\program Files (x86)\windows kits\10\debuggers\)" SIC_ARCH
        R"(\symsrv.dll)");

    const bool Dbghelp = fs::exists(DefaultDbghelpLocation);
    const bool Symsrv = fs::exists(DefaultSymsrvLocation);

    //
    // If they don't exist and we haven't them ourselves, then we have to
    // exit.
    //

    if (!Dbghelp || !Symsrv) {
      printf("The debugger class expects dbghelp.dll / symsrv.dll in the "
             "directory "
             "where the application is running from.\n");
      return false;
    }

    //
    // Sounds like we are able to fix the problem ourselves. Copy the files in
    // the directory where the application is running from and move on!
    //

    fs::copy(DefaultDbghelpLocation, ParentDir);
    fs::copy(DefaultSymsrvLocation, ParentDir);
    printf("Copied dbghelp and symsrv.dll from default location into the "
           "executable directory..\n");
  }

  //
  // Initialize dbghelp.
  //

  const ScopedSymInit Sym(SYMOPT_CASE_INSENSITIVE | SYMOPT_UNDNAME);

  //
  // Grab offsets off nt.
  //

  if (!GetFieldOffsetFromModule(LR"(c:\windows\system32\ntoskrnl.exe)",
                                L"_EPROCESS", L"VadRoot",
                                &SicOffsets.EPROCESSToVadRoot)) {
    printf("Failed to grab nt!_EPROCESS.VadRoot offset.\n");
    return false;
  }

  if (!GetFieldOffsetFromModule(LR"(c:\windows\system32\ntoskrnl.exe)",
                                L"_MMVAD_SHORT", L"u",
                                &SicOffsets.MMVAD_SHORTToVadFlags)) {
    printf("Failed to grab nt!_MMVAD_SHORT.u.VadFlags offset.\n");
    return false;
  }

  if (!GetFieldOffsetFromModule(
          LR"(c:\windows\system32\ntoskrnl.exe)", L"_MMVAD_FLAGS",
          L"PrivateMemory", &SicOffsets.MMVAD_FLAGSPrivateMemoryBitPosition)) {
    printf("Failed to grab nt!_MMVAD_FLAGS.PrivateMemory bit position.\n");
    return false;
  }

  return true;
}