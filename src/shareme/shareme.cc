// Axel '0vercl0k' Souchet - January 23 2020
#include <windows.h>
#include <tchar.h>
#include "..\common\common-user.h"
#include <cstdio>
#include <cstdint>
#include <cstdlib>

//
// The size of a page in bytes.
//

const uint32_t OnePage = 0x1000;

//
// The number of child processes that the parent creates.
//

const uint32_t ChildNumber = 5;

bool
SpawnChild(const HANDLE Shm)

/*++

Routine Description:

    Spawn a child process and passes the `Shm` handle value via the
    command line.

Arguments:

    Shm - The handle to pass to the child process.

Return Value:

    true if success, false otherwise.

--*/

{
    const size_t NumberOfChars = 256;

    STARTUPINFO Si;
    PROCESS_INFORMATION Pi;
    TCHAR Application[NumberOfChars];
    TCHAR CommandLine[NumberOfChars];

    //
    // Zero initialize the locals.
    //

    RtlZeroMemory(&Si, sizeof(Si));
    RtlZeroMemory(&Pi, sizeof(Pi));
    RtlZeroMemory(Application, sizeof(Application));
    RtlZeroMemory(CommandLine, sizeof(CommandLine));

    Si.cb = sizeof(Si);

    //
    // First step is to get the path to ourselves so that we can use the path
    // to CreateProcess another instance of ourselves.
    //

    if (GetModuleFileName(GetModuleHandle(nullptr), Application, NumberOfChars - 1) == 0)
    {
        _tprintf(_T("Failed to GetModuleFileName, GLE=%d.\n"), GetLastError());
        return false;
    }

    //
    // Format a command-line and pass the HANDLE value. The child process will then
    // be able to use it to map a view of the section.
    // Note that inherited handles have the same value which makes it easy for us. Here
    // is a quote from the documentation:
    // """
    // [...] An inherited handle refers to the same object in the child process as
    // it does in the parent process. It also has the same value and access privileges.
    // """
    // https://docs.microsoft.com/en-us/windows/win32/procthread/inheritance
    //

    if (_stprintf_s(CommandLine, NumberOfChars, _T("%s %p"), Application, Shm) == -1)
    {
        _tprintf(_T("Failed to _stprintf_s.\n"));
        return false;
    }

    //
    // Time to create the process!
    //

    bool Success = CreateProcess(Application, CommandLine, nullptr, nullptr, true, 0, nullptr, nullptr, &Si, &Pi);

    //
    // Close the handles we don't need.
    //

    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
    return Success;
}

PVOID
MapShmByHandle(const HANDLE Shm)

/*++

Routine Description:

    Map a view of a section into the current address-space.

Arguments:

    Shm - The handle to pass to the child process.

Return Value:

    The address of the view or nullptr otherwise.

--*/

{
    //
    // Map a view of the shared memory.
    //

    PVOID ViewBaseAddress = MapViewOfFile(Shm, FILE_MAP_WRITE, 0, 0, OnePage);

    if (ViewBaseAddress == nullptr)
    {
        _tprintf(_T("Failed to MapViewOfFile, GLE=%d.\n"), GetLastError());
        return nullptr;
    }

    return ViewBaseAddress;
}

bool
CreateShmChildProcessesAndWait()

/*++

Routine Description:

    Create a shared section, a number of child processes and wait for some user
    input to terminate all the processes.

Arguments:

    None.

Return Value:

    true if success, false otherwise.

--*/

{
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

    const ScopedHandle Shm(
        CreateFileMapping(INVALID_HANDLE_VALUE, &SecAttributes, PAGE_READWRITE, 0, OnePage, nullptr));

    if (!Shm.Valid())
    {
        _tprintf(_T("Failed to CreateFileMapping, GLE=%d.\n"), GetLastError());
        return false;
    }

    //
    // We also create an inheritable event that child processes can wait on.
    // The parent process uses this mechanism to signal the child processes to
    // terminate themselves.
    //

    ScopedHandle Event(CreateEvent(&SecAttributes, true, false, nullptr));

    //
    // To pass the handle value to the children, we simply use the shared memory that every
    // child have mapped in their address space. This way we don't need to pass the handle
    // value via the command line for example.
    //

    HANDLE *View = (HANDLE *)MapShmByHandle(Shm);
    if (View == nullptr)
    {
        _tprintf(_T("Failed to MapShmByHandle.\n"));
        return false;
    }

    *View = Event;

    //
    // Create a number of child processes.
    //

    for (uint32_t Idx = 0; Idx < ChildNumber; Idx++)
    {
        if (!SpawnChild(Shm))
        {
            //
            // If we fail to spawn a child process, let's not forget to signal
            // the event in case we still managed to spawn some child processes.
            // This avoids to have zombie child processes.
            //

            SetEvent(Event);

            _tprintf(_T("Failed to SpawnChild, GLE=%d.\n"), GetLastError());
            return false;
        }
    }

    //
    // At this point we spawned the expected number of children, let's just
    // hang out here until the user wants to terminate everything.
    //

    _tprintf(_T("Spawned children, press a key to terminate.\n"));
    getchar();

    //
    // Time to signal the event and have everybody exits their process cleanly.
    //

    SetEvent(Event);
    return true;
}

bool
MapShmByNameAndWait(const TCHAR *HandleString)

/*++

Routine Description:

    Map a view of a shared memory section that has been received via a command line
    argument. As the argument is a string, it converts it to an actual integer before
    mapping a view and waiting on an event controlled by the parent process.

Arguments:

    HandleString - Handle value of the shared memory to map a view of.

Return Value:

    true if success, false otherwise.

--*/

{
    ScopedHandle Shm(HANDLE(_tcstoull(HandleString, nullptr, 16)));

    //
    // Map a view of the shared memory section.
    //

    const HANDLE *ViewBaseAddress = (HANDLE *)MapShmByHandle(Shm);

    //
    // Once we mapped a view in the address space, we don't need the handle anymore.
    //

    Shm.Close();

    if (ViewBaseAddress == nullptr)
    {
        _tprintf(_T("Failed to MapShmByHandle.\n"));
        return false;
    }

    //
    // Print out who we are and where the view is mapped.
    //

    _tprintf(_T("PID:%d mapped a view at %p.\n"), GetCurrentProcessId(), ViewBaseAddress);

    //
    // Now we can just chill here waiting for the event to be signaled. Remember that
    // the parent process wrote the handle value in the shared memory.
    //

    const ScopedHandle Event(*ViewBaseAddress);
    WaitForSingleObject(Event, INFINITE);
    return true;
}

void
Usage()

/*++

Routine Description:

    Display valid invocation of the program.

Arguments:

    None.

Return Value:

    None.

--*/

{
    _tprintf(_T("shareme.exe\n"));
    _tprintf(_T("shareme.exe <shm handle>\n"));
}

int
_tmain(int argc, TCHAR *argv[])
{
    //
    // No arguments are expected for the child creation mode.
    //

    const bool Create = argc == 1;
    if (Create)
    {
        const bool Success = CreateShmChildProcessesAndWait();
        return Success ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    //
    // In order to be able to map a view of the shared memory, child needs
    // to get the handle value passed as a string in the first argument.
    //

    if (argc != 2)
    {
        Usage();
        return EXIT_FAILURE;
    }

    //
    // Once we have the handle value, we can proceed to mapping it.
    //

    const TCHAR *HandleString = argv[1];
    const bool Success = MapShmByNameAndWait(HandleString);
    return Success ? EXIT_SUCCESS : EXIT_FAILURE;
}