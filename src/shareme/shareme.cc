// Axel '0vercl0k' Souchet - January 23 2020
#include <windows.h>
#include <tchar.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>

const uint32_t OnePage = 0x1000;

//
// Ghetto version of base::win::ScopedHandle:
// https://cs.chromium.org/chromium/buildtools/gn/src/base/win/scoped_handle.h
//

class ScopedHandle {
    public:
        explicit ScopedHandle(HANDLE Handle)
        : handle_(Handle) {
        }

        //
        // We explicitely disable copy ctor / assignment operators.
        //

        //ScopedHandle(ScopedHandle &) = delete;
        //void operator=(ScopedHandle &) = delete;

        static bool IsHandleValid(const HANDLE Handle) {
            return Handle != INVALID_HANDLE_VALUE && Handle != nullptr;
        }

        void Close() {
            if(IsHandleValid(handle_)) {
                CloseHandle(handle_);
                handle_ = INVALID_HANDLE_VALUE;
            }
        }

        ~ScopedHandle() {
            Close();
        }

        operator HANDLE() const {
            return handle_;
        }

    private:
        HANDLE handle_;
};

bool SpawnChild(HANDLE Shm) {
    const size_t NumberOfChars = 256;

    STARTUPINFO Si;
    PROCESS_INFORMATION Pi;
    TCHAR Application[NumberOfChars];
    TCHAR CommandLine[NumberOfChars];

    RtlZeroMemory(&Si, sizeof(Si));
    RtlZeroMemory(&Pi, sizeof(Pi));
    RtlZeroMemory(Application, sizeof(Application));
    RtlZeroMemory(CommandLine, sizeof(CommandLine));

    Si.cb = sizeof(Si);

    if(GetModuleFileName(
        GetModuleHandle(nullptr),
        Application,
        NumberOfChars - 1
    ) == 0) {
        _tprintf(_T("Failed to GetModuleFileName, GLE=%d.\n"), GetLastError());
        return false;
    }

    //
    // [...] An inherited handle refers to the same object in the child process as
    // it does in the parent process. It also has the same value and access privileges.
    // https://docs.microsoft.com/en-us/windows/win32/procthread/inheritance
    //

    if(_stprintf_s(
        CommandLine,
        NumberOfChars,
        _T("%s %p"),
        Application,
        Shm
    ) == -1) {
        _tprintf(_T("Failed to _stprintf_s.\n"));
        return false;
    }

    bool Success = CreateProcess(
        Application,
        CommandLine,
        nullptr,
        nullptr,
        true,
        0,
        nullptr,
        nullptr,
        &Si,
        &Pi
    );

    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
    return Success;
}

PVOID ShmMapByHandle(HANDLE Shm) {

    //
    // Map a view of the shared memory.
    //

    PVOID ViewBaseAddress = MapViewOfFile(
        Shm,
        FILE_MAP_WRITE,
        0,
        0,
        OnePage
    );

    if(ViewBaseAddress == nullptr) {
        _tprintf(_T("Failed to MapViewOfFile, GLE=%d.\n"), GetLastError());
        return nullptr;
    }

    return ViewBaseAddress;
}

int ShmCreateAndWait() {

    //
    // Without a `SecAttributes` the handle cannot
    // be inherited in the child processes, which we need.
    //

    SECURITY_ATTRIBUTES SecAttributes;

    RtlZeroMemory(&SecAttributes, sizeof(SecAttributes));
    SecAttributes.bInheritHandle = true;

    //
    // Create a pagefile-backed mapping of a page.
    //

    const ScopedHandle Shm(CreateFileMapping(
        INVALID_HANDLE_VALUE,
        &SecAttributes,
        PAGE_READWRITE,
        0,
        OnePage,
        nullptr
    ));

    if(Shm == nullptr) {
        _tprintf(_T("Failed to CreateFileMapping, GLE=%d.\n"), GetLastError());
        return EXIT_FAILURE;
    }

    ScopedHandle Event(CreateEvent(
        &SecAttributes,
        true,
        false,
        nullptr
    ));

    HANDLE *View = (HANDLE*)ShmMapByHandle(Shm);
    *View = Event;

    const uint32_t ChildNumber = 5;
    for(uint32_t Idx = 0; Idx < ChildNumber; Idx++) {
        if(!SpawnChild(Shm)) {
            _tprintf(_T("Failed to SpawnChild, GLE=%d.\n"), GetLastError());
            return EXIT_FAILURE;
        }
    }

    _tprintf(_T("Spawned children, press a key to terminate.\n"));
    getchar();

    SetEvent(Event);
    return EXIT_SUCCESS;
}

int ShmMapByNameAndWait(const TCHAR *HandleString) {
    ScopedHandle Shm(HANDLE(_tcstoull(
        HandleString,
        nullptr,
        16
    )));

    //
    // Display the base address of the view and exit. Note that we don't unmap the view
    // as we want it to be resident in the process so that we can inspect it.
    //

    const HANDLE *ViewBaseAddress = (HANDLE*)ShmMapByHandle(Shm);
    Shm.Close();

    if(ViewBaseAddress == nullptr) {
        _tprintf(_T("Failed to ShmMapSection.\n"));
        return EXIT_FAILURE;
    }

    _tprintf(_T("PID:%d mapped a view at %p\n"), GetCurrentProcessId(), ViewBaseAddress);

    const ScopedHandle Event(*ViewBaseAddress);
    WaitForSingleObject(Event, INFINITE);
    return EXIT_SUCCESS;
}

void Usage() {
    _tprintf(_T("shareme.exe\n"));
    _tprintf(_T("shareme.exe <shm handle>\n"));
}

int _tmain(int argc, TCHAR *argv[]) {

    //
    // We only accept two options, so this is pretty straight-forward.
    //

    const bool Create = argc == 1;
    if(Create) {
        return ShmCreateAndWait();
    }

    if(argc != 2) {
        Usage();
        return EXIT_FAILURE;
    }

    const TCHAR *HandleString = argv[1];
    return ShmMapByNameAndWait(HandleString);
}