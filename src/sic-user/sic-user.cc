// Axel '0vercl0k' Souchet - February 18 2020
#include "..\common\common-user.h"
#include "..\common\common.h"
#include "install.h"
#include "sym.h"
#include "utils.h"
#include <CLI/CLI.hpp>
#include <cstdio>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>
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

struct Opts_t {
  std::string ProcessName;
};

int main(int argc, char *argv[]) {
  Opts_t Opts;
  CLI::App Sic("SiC - Enumerate shared-memory mappings on Windows");

  Sic.allow_windows_style_options();
  Sic.set_help_all_flag("--help-all", "Expand all help");
  Sic.add_option("-p,--process", Opts.ProcessName,
                 "Filter mapping mapped by process names");

  CLI11_PARSE(Sic, argc, argv);

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

  const ScopedHandle_t SicDevice =
      CreateFileA(DeviceName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

  if (!SicDevice.Valid()) {
    printf("Could not open the sic device.\n");
    return EXIT_FAILURE;
  }

  //
  // Initialize the offsets that the driver needs.
  //

  DWORD BytesReturned;
  if (!DeviceIoControl(SicDevice, IOCTL_SIC_INIT_CONTEXT, &SicOffsets,
                       sizeof(SicOffsets), nullptr, 0, &BytesReturned,
                       nullptr)) {
    printf("IOCTL_SIC_INIT_CONTEXT failed\n");
    return EXIT_FAILURE;
  }

  //
  // Gets the size of the lookup table.
  //

  DWORD64 Size = 0;
  if (!DeviceIoControl(SicDevice, IOCTL_SIC_GET_SHMS_SIZE, nullptr, 0, &Size,
                       sizeof(Size), &BytesReturned, nullptr)) {
    printf("IOCTL_SIC_GET_SHMS_SIZE failed\n");
    return EXIT_FAILURE;
  }

  //
  // Allocate memory and get the shms.
  //

  auto Buffer = std::make_unique<uint8_t[]>(size_t(Size));
  if (!DeviceIoControl(SicDevice, IOCTL_SIC_GET_SHMS, nullptr, 0, Buffer.get(),
                       DWORD(Size), &BytesReturned, nullptr) ||
      BytesReturned != Size) {
    printf("IOCTL_SIC_GET_SHMS failed\n");
    return EXIT_FAILURE;
  }

  //
  // Grab the process list.
  //

  const auto Processes = GetProcessList();
  if (Processes.size() == 0) {
    printf("GetProcessList failed\n");
    return EXIT_FAILURE;
  }

  //
  // Walk the buffer to create various lookup tables.
  //

  using Pte_t = uint64_t;
  using Pid_t = uintptr_t;
  std::unordered_map<Pte_t, std::vector<PSIC_SHARED_MEMORY_OWNER_ENTRY>>
      PteToOwners;
  std::unordered_map<Pid_t, std::vector<PSIC_SHM_ENTRY>> NameToMappings;

  //
  // Start by walking the SHMs..
  //

  const auto Shms = PSIC_SHMS(Buffer.get());
  auto Shm = &Shms->Shms[0];
  for (uint64_t NumberSharedMemory = 0;
       NumberSharedMemory < Shms->NumberSharedMemory; NumberSharedMemory++) {

    //
    // Then, walk the owners..
    //

    std::vector<PSIC_SHARED_MEMORY_OWNER_ENTRY> Owners;
    auto Owner = &Shm->Owners[0];
    for (uint64_t NumberOwners = 0; NumberOwners < Shm->NumberOwners;
         NumberOwners++) {

      //
      // If we have a PID for it, we feed it into our lookups.
      //

      if (Processes.contains(Owner->Pid)) {

        //
        // Default construct the entry if it doesn't exist yet, or do nothing.
        //

        NameToMappings.try_emplace(Owner->Pid, std::vector<PSIC_SHM_ENTRY>());

        //
        // Emplace back the pointer.
        //

        NameToMappings.at(Owner->Pid).emplace_back(Shm);

        //
        // Keep track of this owner.
        //

        Owners.emplace_back(Owner);
      }

      //
      // Go to the next owner.
      //

      Owner++;
    }

    //
    // Go to the next mapping.
    //

    Shm = PSIC_SHM_ENTRY(Owner);
    PteToOwners.emplace(Shm->PrototypePTE, Owners);
  }

  //
  // Do the display now that we have lookups.
  //

  for (const auto &[Pte, Owners] : PteToOwners) {

    //
    // Print out the information regarding the mapping.
    //

    printf("ProtoPTE: %016llx\n", Pte);

    //
    // Iterate through the owners of the mapping.
    //

    for (const auto Owner : Owners) {

      //
      // Print out the information regarding the owner.
      //

      const wchar_t *ProcessName =
          Processes.contains(Owner->Pid)
              ? (wchar_t *)Processes.at(Owner->Pid).c_str()
              : L"Unknown";

      printf("  Name: %ws (PID: %lld, EPROCESS: %016llx) at %016llx-%016llx\n",
             ProcessName, Owner->Pid, Owner->Process,
             Owner->StartingVirtualAddress, Owner->EndingVirtualAddress);
    }
  }

  return EXIT_SUCCESS;
}
