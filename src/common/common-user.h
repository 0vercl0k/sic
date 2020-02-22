// Axel '0vercl0k' Souchet - February 20 2020
#pragma once

#include <windows.h>

//
// Ghetto version of base::win::ScopedHandle:
// https://cs.chromium.org/chromium/buildtools/gn/src/base/win/scoped_handle.h
//

class ScopedHandle
{
public:
    explicit ScopedHandle(HANDLE Handle) : handle_(Handle) {}

    //
    // We explicitely disable copy ctor / assignment operators.
    //

    // ScopedHandle(ScopedHandle &) = delete;
    // void operator=(ScopedHandle &) = delete;

    static bool IsHandleValid(const HANDLE Handle) { return Handle != INVALID_HANDLE_VALUE && Handle != nullptr; }

    void Close()
    {
        if (IsHandleValid(handle_))
        {
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
    }

    bool Valid() const { return IsHandleValid(handle_); }
    ~ScopedHandle() { Close(); }

    operator HANDLE() const { return handle_; }

private:
    HANDLE handle_;
};