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

//
// Various defines.
//

const char *ServiceName = "sic";
const char *ServiceDisplayName = "Sharing Is Caring Driver";
const char *ServiceFilename = "sic-drv.sys";
const char *DeviceName = R"(\\.\)" SIC_DEVICE_NAME;

//
// Options.
//

struct Opts_t {
  std::string Filter;
};

int main(int argc, char *argv[]) {
  Opts_t Opts;
  CLI::App Sic("SiC - Enumerate shared-memory mappings on Windows");

  Sic.allow_windows_style_options();
  Sic.set_help_all_flag("--help-all", "Expand all help");
  Sic.add_option("-f,--filer", Opts.Filter,
                 "Only display shms owned by processes matching this filter");

  CLI11_PARSE(Sic, argc, argv);

  //
  // Always stop and remove the driver on exit.
  //

  const auto OnExit = ScopeExit_t([&]() {
    StopDriver(ServiceName);
    RemoveDriver(ServiceName);
  });

  SIC_OFFSETS SicOffsets;
  RtlZeroMemory(&SicOffsets, sizeof(SicOffsets));

  //
  // Grab offsets.
  //

  if (!GetOffsets(SicOffsets)) {
    printf("Failed to grab offsets.\n");
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

  //
  // Start the driver.
  //

  if (!StartDriver(ServiceName)) {
    printf("StartDriver failed.\n");
    return EXIT_FAILURE;
  }

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

  std::vector<PSIC_SHM_ENTRY> ShmsToDisplay;

  //
  // Let's start by walking the SHMs..
  //

  const auto Shms = PSIC_SHMS(Buffer.get());
  auto Shm = &Shms->Shms[0];
  for (uint64_t NumberSharedMemory = 0;
       NumberSharedMemory < Shms->NumberSharedMemory; NumberSharedMemory++) {

    //
    // Then, walk the owners..
    //

    auto Owner = &Shm->Owners[0];
    bool ToAdd = true;
    for (uint64_t NumberOwners = 0; NumberOwners < Shm->NumberOwners;
         NumberOwners++) {

      //
      // If we have a filter, then let's see if we have a match.
      //

      if (Opts.Filter != "" && Processes.contains(Owner->Pid)) {

        //
        // If we have a match, then feed it into the to display list.
        //

        const std::string &CurrentProcessName = Processes.at(Owner->Pid);
        ToAdd = CurrentProcessName.find(Opts.Filter) != CurrentProcessName.npos;
      }

      //
      // Go to the next owner.
      //

      Owner++;
    }

    //
    // If we selected this shm, let's feed it into the list.
    //

    if (ToAdd) {
      ShmsToDisplay.emplace_back(Shm);
    }

    //
    // Go to the next mapping.
    //

    Shm = PSIC_SHM_ENTRY(Owner);
  }

  //
  // Do the display now that we have lookups.
  //

  for (const auto &ShmToDisplay : ShmsToDisplay) {

    //
    // Print out the information regarding the mapping.
    //

    printf("ProtoPTE: %016llx\n", ShmToDisplay->PrototypePTE);

    //
    // Iterate through the owners of the mapping.
    //

    for (uint64_t Idx = 0; Idx < ShmToDisplay->NumberOwners; Idx++) {

      //
      // Print out the information regarding the owner.
      //

      const auto Owner = &ShmToDisplay->Owners[Idx];
      const std::string &ProcessName = Processes.at(Owner->Pid);

      printf("  Name: %s (PID: %lld, EPROCESS: %016llx) at %016llx-%016llx\n",
             ProcessName.c_str(), Owner->Pid, Owner->Process,
             Owner->StartingVirtualAddress, Owner->EndingVirtualAddress);
    }
  }

  return EXIT_SUCCESS;
}
