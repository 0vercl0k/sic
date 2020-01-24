// Axel '0vercl0k' Souchet - January 23 2020
#include <windows.h>
#include <tchar.h>
#include <cstdio>
#include <cstdint>

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

        ~ScopedHandle() {
            if(IsHandleValid(handle_)) {
                //CloseHandle(handle_);
            }
        }

        operator HANDLE() const {
            return handle_;
        }

    private:
        HANDLE handle_;
};

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

int ShmCreate(const TCHAR *Name) {

    //
    // Create a pagefile-backed mapping of a page. Note that
    // we don't use a ScopedHandle as we want the handle to be resident
    // so that clients can connect to it.
    //

    const HANDLE Shm(CreateFileMapping(
        INVALID_HANDLE_VALUE,
        nullptr,
        PAGE_READWRITE,
        0,
        OnePage,
        Name
    ));

    if(Shm == nullptr) {
        _tprintf(_T("Failed to CreateFileMapping, GLE=%d.\n"), GetLastError());
        return EXIT_FAILURE;
    }

    //
    // Map a view of the shared memory.
    //

    const PVOID ViewBaseAddress = ShmMapByHandle(Shm);

    if(ViewBaseAddress == nullptr) {
        _tprintf(_T("Failed to ShmMapSection.\n"));
        return EXIT_FAILURE;
    }

    //
    // Display the base address of the view and exit. Note that we don't unmap the view
    // as we want it to be resident in the process so that we can inspect it.
    //

    _tprintf(_T("Mapped '%s' at %p\n"), Name, ViewBaseAddress);
    return EXIT_SUCCESS;
}

int ShmMapByName(const TCHAR *Name) {
    ScopedHandle Shm(OpenFileMapping(
        FILE_MAP_WRITE,
        false,
        Name
    ));

    if(Shm == nullptr) {
        _tprintf(_T("Failed to OpenFileMapping('%s'), GLE=%d.\n"), Name, GetLastError());
        return EXIT_FAILURE;
    }

    //
    // Display the base address of the view and exit. Note that we don't unmap the view
    // as we want it to be resident in the process so that we can inspect it.
    //

    const PVOID ViewBaseAddress = ShmMapByHandle(Shm);

    if(ViewBaseAddress == nullptr) {
        _tprintf(_T("Failed to ShmMapSection.\n"));
        return EXIT_FAILURE;
    }

    _tprintf(_T("Mapped '%s' at %p\n"), Name, ViewBaseAddress);
    return EXIT_SUCCESS;
}

void Usage() {
    _tprintf(_T("shareme.exe <create|map> <shm name>\n"));
}

int _tmain(int argc, TCHAR *argv[]) {
    if(argc != 3) {
        Usage();
        return EXIT_FAILURE;
    }

    //
    // We only accept two options, so this is pretty straight-forward.
    //

    const bool Create = _tcsicmp(argv[1], _T("create")) == 0;
    const bool Map = _tcsicmp(argv[1], _T("map")) == 0;
    const TCHAR *Name = argv[2];

    //
    // If the user didn't provide a valid option we also print the usage.
    //

    if(!Create && !Map) {
        Usage();
        return EXIT_FAILURE;
    }

    //
    // We can now either create a mapping or map it.
    //

    int Status = Create ? ShmCreate(Name) : ShmMapByName(Name);

    //
    // Exit the program is something failed along the way.
    //

    if(Status == EXIT_FAILURE) {
        return Status;
    }

    //
    // If everything went well, we wait for a user input.
    //

    _tprintf(_T("Press a key to exit the program.\n"));
    getchar();

    //
    // Our job is done!.
    //

    return Status;
}