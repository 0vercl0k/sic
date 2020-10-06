// Axel '0vercl0k' Souchet - February 18 2020
#include "..\common\common-user.h"
#include "..\common\common.h"
#include "install.h"
#include "sym.h"
#include <cstdio>
#include <filesystem>
#include <windows.h>

#if defined(__i386__) || defined(_M_IX86)
#define SIC_ARCH "x86"
#elif defined(__amd64__) || defined(_M_X64)
#define SIC_ARCH "x64"
#else
#error Platform not supported.
#endif

namespace fs = std::filesystem;

const char *ServiceName = "sic";
const char *ServiceDisplayName = "Sharing Is Caring Driver";
const char *ServiceFilename = "sic-drv.sys";
const char *DeviceName = R"(\\.\)" SIC_DEVICE_NAME;

#if 0
void SicGetProcessList(PSYSTEM_PROCESS_INFORMATION *ProcessList)

{
  const UINT32 MaxAttempts = 10;
  NTSTATUS Status = STATUS_SUCCESS;

  PAGED_CODE();

  //
  // Initialize the output buffer to NULL.
  //

  *ProcessList = NULL;

  //
  // If we didn't receive a ProcessList, we fail the call as we
  // expect one.
  //

  if (!ARGUMENT_PRESENT(ProcessList)) {
    Status = STATUS_INVALID_PARAMETER;
    goto clean;
  }

  //
  // Try out to get a process list in a maximum number of attempts.
  // We do this because we can encounter racy behavior where the world
  // changes in between the two ZwQuerySystemInformation.. sigh.
  //

  for (UINT32 Attempt = 0; Attempt < MaxAttempts; Attempt++) {
    ULONG ReturnLength = 0;
    PVOID LocalProcessList = NULL;

    //
    // How much space do we need?
    //

    Status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0,
                                      &ReturnLength);

    //
    // Allocate memory to receive the process list.
    //

    LocalProcessList =
        ExAllocatePoolZero(PagedPool, ReturnLength, SIC_MEMORY_TAG);

    if (LocalProcessList == NULL) {
      Status = STATUS_INSUFFICIENT_RESOURCES;
      goto clean;
    }

    //
    // Get a list of the processes running on the system.
    //

    Status =
        ZwQuerySystemInformation(SystemProcessInformation, LocalProcessList,
                                 ReturnLength, &ReturnLength);

    //
    // If we fail, let's clean up behind ourselves, and give it another try!
    //

    if (!NT_SUCCESS(Status)) {
      ExFreePoolWithTag(LocalProcessList, SIC_MEMORY_TAG);

      LocalProcessList = NULL;
      continue;
    }

    //
    // If we make it here, it means that we have our list and we are done.
    //

    *ProcessList = LocalProcessList;

    LocalProcessList = NULL;
    break;
  }

clean:

  //
  // If we managed to get the list, it's all good otherwise it's a failure.
  //

  return Status;
}
#endif

int main() {
  //
  // Always stop and remove the driver on exit.
  //

  const auto OnExit = ScopeExit_t([&]() {
    StopDriver(ServiceName);
    RemoveDriver(ServiceName);
  });

  //
  // Ensure that we both have dbghelp.dll and symsrv.dll in the current
  // directory otherwise things don't work. cf
  // https://docs.microsoft.com/en-us/windows/win32/debug/using-symsrv
  // "Installation"
  //

  char ExePathBuffer[MAX_PATH];
  if (!GetModuleFileNameA(nullptr, &ExePathBuffer[0], sizeof(ExePathBuffer))) {
    printf("GetModuleFileNameA failed.\n");
    return EXIT_FAILURE;
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
      return EXIT_FAILURE;
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

  SIC_OFFSETS SicOffsets;
  RtlZeroMemory(&SicOffsets, sizeof(SicOffsets));

  //
  // Grab offsets.
  //

  printf("Grabbing offsets...\n");

  if (!GetFieldOffsetFromModule(LR"(c:\windows\system32\ntoskrnl.exe)",
                                L"_EPROCESS", L"VadRoot",
                                &SicOffsets.EPROCESSToVadRoot)) {
    printf("Failed to grab nt!_EPROCESS.VadRoot offset.\n");
    return EXIT_FAILURE;
  }

  if (!GetFieldOffsetFromModule(LR"(c:\windows\system32\ntoskrnl.exe)",
                                L"_MMVAD_SHORT", L"u",
                                &SicOffsets.MMVAD_SHORTToVadFlags)) {
    printf("Failed to grab nt!_MMVAD_SHORT.u.VadFlags offset.\n");
    return EXIT_FAILURE;
  }

  if (!GetFieldOffsetFromModule(
          LR"(c:\windows\system32\ntoskrnl.exe)", L"_MMVAD_FLAGS",
          L"PrivateMemory", &SicOffsets.MMVAD_FLAGSPrivateMemoryBitPosition)) {
    printf("Failed to grab nt!_MMVAD_FLAGS.PrivateMemory bit position.\n");
    return EXIT_FAILURE;
  }

  //
  // Install the driver.
  //

  if (!InstallDriver(ServiceName, ServiceDisplayName, ServiceFilename)) {
    printf(
        "InstallDriver failed; are you running this from an admin prompt?\n");
    return EXIT_FAILURE;
  }

  printf("Driver installed.\n");

  //
  // Start the driver.
  //

  if (!StartDriver(ServiceName)) {
    printf("StartDriver failed.\n");
    return EXIT_FAILURE;
  }

  printf("Start driver.\n");

  //
  // Get a handle to the device.
  //

  ScopedHandle_t Sic =
      CreateFileA(DeviceName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

  if (!Sic.Valid()) {
    printf("Could not open the sic device.\n");
    return EXIT_FAILURE;
  }

  //
  // Initialize the offsets that the driver needs.
  //

  DWORD BytesReturned;
  if (!DeviceIoControl(Sic, IOCTL_SIC_INIT_CONTEXT, &SicOffsets,
                       sizeof(SicOffsets), nullptr, 0, &BytesReturned,
                       nullptr)) {
    printf("IOCTL_SIC_INIT_CONTEXT failed\n");
    return EXIT_FAILURE;
  }

  //
  // Gets the size of the lookup table.
  //

  DWORD64 Size = 0;
  if (!DeviceIoControl(Sic, IOCTL_SIC_GET_SHMS_SIZE, nullptr, 0, &Size,
                       sizeof(Size), &BytesReturned, nullptr)) {
    printf("IOCTL_SIC_GET_SHMS_SIZE failed\n");
    return EXIT_FAILURE;
  }

  //
  // Allocate memory and get the shms.
  //

  auto Buffer = std::make_unique<uint8_t[]>(size_t(Size));
  if (!DeviceIoControl(Sic, IOCTL_SIC_GET_SHMS, nullptr, 0, Buffer.get(),
                       DWORD(Size), &BytesReturned, nullptr) ||
      BytesReturned != Size) {
    printf("IOCTL_SIC_GET_SHMS failed\n");
    return EXIT_FAILURE;
  }

  //
  // Walk the buffer.
  //

  const auto Shms = PSIC_SHMS(Buffer.get());
  auto Shm = &Shms->Shms[0];
  for (DWORD64 NumberSharedMemory = 0;
       NumberSharedMemory < Shms->NumberSharedMemory; NumberSharedMemory++) {
    //
    // Print out the information regarding the mapping.
    //

    printf("ProtoPTE: %016llx\n", Shm->PrototypePTE);

    //
    // Iterate through the owners of the mapping.
    //

    auto Owner = &Shm->Owners[0];
    for (DWORD64 NumberOwners = 0; NumberOwners < Shm->NumberOwners;
         NumberOwners++) {

      //
      // Print out the information regarding the owner.
      //

      printf("  Owner: %016llx at %016llx-%016llx\n", Owner->Process,
             Owner->StartingVirtualAddress, Owner->EndingVirtualAddress);

      //
      // Go to the next owner.
      //

      Owner++;
    }

    //
    // Go to the next mapping.
    //

    Shm = PSIC_SHM_ENTRY(Owner);
  }

  return EXIT_SUCCESS;
}
