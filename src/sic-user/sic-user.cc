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

int main() {
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

  ScopedSymInit Sym(SYMOPT_CASE_INSENSITIVE | SYMOPT_UNDNAME);

  SIC_CONTEXT SicCtx;
  RtlZeroMemory(&SicCtx, sizeof(SicCtx));

  //
  // Grab offsets.
  //

  printf("Grabbing offsets...\n");

  if (!GetFieldOffsetFromModule(LR"(c:\windows\system32\ntoskrnl.exe)",
                                L"_EPROCESS", L"VadRoot",
                                &SicCtx.Offsets.EPROCESSToVadRoot)) {
    printf("Failed to grab nt!_EPROCESS.VadRoot offset.\n");
    return EXIT_FAILURE;
  }

  if (!GetFieldOffsetFromModule(LR"(c:\windows\system32\ntoskrnl.exe)",
                                L"_MMVAD_SHORT", L"u",
                                &SicCtx.Offsets.MMVAD_SHORTToVadFlags)) {
    printf("Failed to grab nt!_MMVAD_SHORT.u.VadFlags offset.\n");
    return EXIT_FAILURE;
  }

  if (!GetFieldOffsetFromModule(
          LR"(c:\windows\system32\ntoskrnl.exe)", L"_MMVAD_FLAGS",
          L"PrivateMemory",
          &SicCtx.Offsets.MMVAD_FLAGSPrivateMemoryBitPosition)) {
    printf("Failed to grab nt!_MMVAD_FLAGS.PrivateMemory bit position.\n");
    return EXIT_FAILURE;
  }

  //
  // Install the driver.
  //

  const char *ServiceName = "sic";
  const char *ServiceDisplayName = "Sharing Is Caring Driver";
  const char *ServiceFilename = "sic-drv.sys";

  if (!InstallDriver(ServiceName, ServiceDisplayName, ServiceFilename)) {
    printf("InstallDriver failed.\n");
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

  ScopedHandle Sic(CreateFileA(R"(\\.\SoSIC)", GENERIC_READ | GENERIC_WRITE, 0,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                               nullptr));

  if (!Sic.Valid()) {
    printf("Could not open the sic device.\n");
    return EXIT_FAILURE;
  }

  DWORD BytesReturned;
  DeviceIoControl(Sic, IOCTL_SIC_INIT_CONTEXT, &SicCtx, sizeof(SicCtx), nullptr,
                  0, &BytesReturned, nullptr);
  DeviceIoControl(Sic, IOCTL_SIC_ENUM_SHMS, nullptr, 0, nullptr, 0,
                  &BytesReturned, nullptr);
  Sic.Close();

  printf("Stopping the driver: %d\n", StopDriver(ServiceName));
  printf("Removing the driver: %d\n", RemoveDriver(ServiceName));
  return EXIT_SUCCESS;
}
