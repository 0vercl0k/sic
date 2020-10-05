// Axel '0vercl0k' Souchet - February 20 2020
#pragma once

#include <windows.h>

//
// Ghetto version of base::win::ScopedHandle:
// https://cs.chromium.org/chromium/buildtools/gn/src/base/win/scoped_handle.h
//

class ScopedHandle
{
private:
    HANDLE Handle_;

public:
    explicit ScopedHandle(const HANDLE Handle) : Handle_(Handle) {}
    ~ScopedHandle() { Close(); }

    //
    // Rule of three.
    //

    ScopedHandle(const ScopedHandle &) = delete;
    ScopedHandle &operator=(const ScopedHandle &) = delete;

    static bool IsHandleValid(const HANDLE Handle) { return Handle != INVALID_HANDLE_VALUE && Handle != nullptr; }

    void Close()
    {
        if (IsHandleValid(Handle_))
        {
            CloseHandle(Handle_);
            Handle_ = INVALID_HANDLE_VALUE;
        }
    }

    bool Valid() const { return IsHandleValid(Handle_); }

    operator HANDLE() const { return Handle_; }
};