// Axel '0vercl0k' Souchet - February 22 2020
#include "install.h"

#include <filesystem>

namespace fs = std::filesystem;

bool
InstallDriver(const TCHAR *ServiceName, const TCHAR *ServiceDisplayName, const TCHAR *ServiceFilename)
{
    const SC_HANDLE Scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (Scm == nullptr)
    {
        return false;
    }

    const fs::path SicPath = fs::current_path() / ServiceFilename;
    const SC_HANDLE Service = CreateService(
        Scm,
        ServiceName,
        ServiceDisplayName,
        0,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_SEVERE,
        SicPath.c_str(),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr);

    CloseServiceHandle(Scm);

    if (Service != nullptr)
    {
        CloseServiceHandle(Service);
        return true;
    }

    const bool AlreadyExists = GetLastError() == ERROR_SERVICE_EXISTS;
    return AlreadyExists;
}

bool
StartDriver(const TCHAR *ServiceName)
{
    const SC_HANDLE Scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);

    if (Scm == nullptr)
    {
        return false;
    }

    const SC_HANDLE Service = OpenService(Scm, ServiceName, SERVICE_START);

    if (Service == nullptr)
    {
        CloseServiceHandle(Scm);
        return false;
    }

    const BOOL Success = StartService(Service, 0, nullptr);
    CloseServiceHandle(Scm);
    CloseServiceHandle(Service);
    return Success || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
}

bool
StopDriver(const TCHAR *ServiceName)
{
    const SC_HANDLE Scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);

    if (Scm == nullptr)
    {
        return false;
    }

    const SC_HANDLE Service = OpenService(Scm, ServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);

    if (Service == nullptr)
    {
        CloseServiceHandle(Scm);
        return false;
    }

    SERVICE_STATUS_PROCESS Status;
    static_assert(sizeof(Status) > sizeof(SERVICE_STATUS));
    static_assert(FIELD_OFFSET(SERVICE_STATUS_PROCESS, dwCurrentState) == FIELD_OFFSET(SERVICE_STATUS, dwCurrentState));
    static_assert(FIELD_OFFSET(SERVICE_STATUS_PROCESS, dwWaitHint) == FIELD_OFFSET(SERVICE_STATUS, dwWaitHint));

    BOOL Success = ControlService(Service, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&Status);
    while (Success && Status.dwCurrentState != SERVICE_STOPPED)
    {
        _tprintf(_T("Waiting for %d.."), Status.dwWaitHint);
        Sleep(Status.dwWaitHint);
        DWORD BytesNeeded;
        Success = QueryServiceStatusEx(Service, SC_STATUS_PROCESS_INFO, (LPBYTE)&Status, sizeof(Status), &BytesNeeded);
        _tprintf(_T("Success: %d, dwCurrentState: %d.."), Success, Status.dwCurrentState);
    }

    CloseServiceHandle(Scm);
    CloseServiceHandle(Service);
    return Success && Status.dwCurrentState == SERVICE_STOPPED;
}

bool
RemoveDriver(const TCHAR *ServiceName)
{
    const SC_HANDLE Scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);

    if (Scm == nullptr)
    {
        return false;
    }

    const SC_HANDLE Service = OpenService(Scm, ServiceName, DELETE);

    if (Service == nullptr)
    {
        return false;
    }

    const bool Success = DeleteService(Service);
    CloseServiceHandle(Scm);
    CloseServiceHandle(Service);
    return Success;
}
