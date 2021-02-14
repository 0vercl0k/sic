// Axel '0vercl0k' Souchet - February 22 2020
#include "install.h"
#include "../common/common-user.h"

#include <filesystem>

namespace fs = std::filesystem;

bool InstallDriver(const char *ServiceName, const char *ServiceDisplayName,
                   const char *ServiceFilename) {
  const ScopedServiceHandle_t Scm =
      OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
  if (Scm == nullptr) {
    return false;
  }

  const fs::path SicPath = fs::current_path() / ServiceFilename;
  if (!fs::exists(SicPath)) {
    printf("%s does not exist, exiting\n", SicPath.string().c_str());
    return false;
  }

  const ScopedServiceHandle_t Service = CreateServiceA(
      Scm, ServiceName, ServiceDisplayName, 0, SERVICE_KERNEL_DRIVER,
      SERVICE_DEMAND_START, SERVICE_ERROR_SEVERE, SicPath.string().c_str(),
      nullptr, nullptr, nullptr, nullptr, nullptr);

  if (Service != nullptr) {
    return true;
  }

  const bool AlreadyExists = GetLastError() == ERROR_SERVICE_EXISTS;
  return AlreadyExists;
}

bool StartDriver(const char *ServiceName) {
  const ScopedServiceHandle_t Scm =
      OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);

  if (Scm == nullptr) {
    return false;
  }

  const ScopedServiceHandle_t Service =
      OpenService(Scm, ServiceName, SERVICE_START);

  if (Service == nullptr) {
    return false;
  }

  const BOOL Success = StartService(Service, 0, nullptr);
  return Success || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
}

bool StopDriver(const char *ServiceName) {
  const ScopedServiceHandle_t Scm =
      OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);

  if (Scm == nullptr) {
    return false;
  }

  const ScopedServiceHandle_t Service =
      OpenService(Scm, ServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);

  if (Service == nullptr) {
    return false;
  }

  SERVICE_STATUS_PROCESS Status;
  static_assert(sizeof(Status) > sizeof(SERVICE_STATUS));
  static_assert(FIELD_OFFSET(SERVICE_STATUS_PROCESS, dwCurrentState) ==
                FIELD_OFFSET(SERVICE_STATUS, dwCurrentState));
  static_assert(FIELD_OFFSET(SERVICE_STATUS_PROCESS, dwWaitHint) ==
                FIELD_OFFSET(SERVICE_STATUS, dwWaitHint));

  BOOL Success =
      ControlService(Service, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&Status);
  while (Success && Status.dwCurrentState != SERVICE_STOPPED) {
    printf("Waiting for %u..\n", Status.dwWaitHint);
    Sleep(Status.dwWaitHint);
    DWORD BytesNeeded;
    Success =
        QueryServiceStatusEx(Service, SC_STATUS_PROCESS_INFO, (LPBYTE)&Status,
                             sizeof(Status), &BytesNeeded);
    printf("Success: %d, dwCurrentState: %u..\n", Success,
           Status.dwCurrentState);
  }

  return Success && Status.dwCurrentState == SERVICE_STOPPED;
}

bool RemoveDriver(const char *ServiceName) {
  const ScopedServiceHandle_t Scm =
      OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);

  if (Scm == nullptr) {
    return false;
  }

  const ScopedServiceHandle_t Service = OpenService(Scm, ServiceName, DELETE);

  if (Service == nullptr) {
    return false;
  }

  const bool Success = DeleteService(Service);
  return Success;
}
