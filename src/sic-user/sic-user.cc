// Axel '0vercl0k' Souchet - February 18 2020
#include <windows.h>
#include <tchar.h>
#include "sym.h"
#include "..\common\common.h"
#include "..\common\common-user.h"

#include <cstdio>
#include <filesystem>

// https://github.com/microsoft/Windows-driver-samples/blob/master/general/ioctl/wdm/exe/install.c

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

int
_tmain()
{
    //
    // Initialize dbghelp.
    //

    ScopedSymInit Sym(SYMOPT_CASE_INSENSITIVE | SYMOPT_UNDNAME);

    SIC_CONTEXT SicCtx;

    RtlZeroMemory(&SicCtx, sizeof(SicCtx));

    //
    // Grab offsets.
    //

    _tprintf(
        _T("Make sure to have dbghelp.dll in the current directory, symsrv.dll and internet connection or the ntkrnlmp.pdb file if offline.\n"));

    _tprintf(_T("Grabbing offsets...\n"));

    if (!GetFieldOffsetFromModule(
            _T(R"(c:\windows\system32\ntoskrnl.exe)"),
            _T("_EPROCESS"),
            _T("VadRoot"),
            &SicCtx.Offsets.EPROCESSToVadRoot))
    {
        _tprintf(_T("Failed to grab nt!_EPROCESS.VadRoot offset.\n"));
        return EXIT_FAILURE;
    }

    if (!GetFieldOffsetFromModule(
            _T(R"(c:\windows\system32\ntoskrnl.exe)"),
            _T("_MMVAD_SHORT"),
            _T("u"),
            &SicCtx.Offsets.MMVAD_SHORTToVadFlags))
    {
        _tprintf(_T("Failed to grab nt!_MMVAD_SHORT.u.VadFlags offset.\n"));
        return EXIT_FAILURE;
    }

    if (!GetFieldOffsetFromModule(
            _T(R"(c:\windows\system32\ntoskrnl.exe)"),
            _T("_MMVAD_FLAGS"),
            _T("PrivateMemory"),
            &SicCtx.Offsets.MMVAD_FLAGSPrivateMemoryBitPosition))
    {
        _tprintf(_T("Failed to grab nt!_MMVAD_FLAGS.PrivateMemory bit position.\n"));
        return EXIT_FAILURE;
    }

    const TCHAR *ServiceName = _T("sic");
    const TCHAR *ServiceDisplayName = _T("Sharing Is Caring Driver");
    const TCHAR *ServiceFilename = _T("sic-drv.sys");

    if (!InstallDriver(ServiceName, ServiceDisplayName, ServiceFilename))
    {
        _tprintf(_T("InstallDriver failed.\n"));
        return EXIT_FAILURE;
    }

    _tprintf(_T("Driver installed.\n"));

    if (!StartDriver(ServiceName))
    {
        _tprintf(_T("StartDriver failed.\n"));
        return EXIT_FAILURE;
    }

    _tprintf(_T("Start driver.\n"));

    //
    // Get a handle to the driver.
    //
    {
        ScopedHandle Sic(CreateFile(
            _T(R"(\\.\SoSIC)"),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr));

        if (!Sic.Valid())
        {
            _tprintf(_T("Could not open the sic device.\n"));
            return EXIT_FAILURE;
        }

        DWORD BytesReturned;
        DeviceIoControl(Sic, IOCTL_SIC_INIT_CONTEXT, &SicCtx, sizeof(SicCtx), nullptr, 0, &BytesReturned, nullptr);
        DeviceIoControl(Sic, IOCTL_SIC_ENUM_SHMS, nullptr, 0, nullptr, 0, &BytesReturned, nullptr);
    }

    _tprintf(_T("Stopping the driver: %d\n"), StopDriver(ServiceName));
    _tprintf(_T("Removing the driver: %d\n"), RemoveDriver(ServiceName));
    return EXIT_SUCCESS;
}
