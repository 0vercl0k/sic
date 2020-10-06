// Axel '0vercl0k' Souchet - February 20 2020
#pragma once

#include <windows.h>

//
// Ghetto version of base::win::ScopedHandle:
// https://cs.chromium.org/chromium/buildtools/gn/src/base/win/scoped_handle.h
//

template <typename _HandleType, typename _Deleter>
class Scoped
{
private:
    _HandleType Handle_;

public:
    Scoped(const _HandleType Handle) : Handle_(Handle) {}

    //
    // Rule of three.
    //

    ~Scoped() { Close(); }
    Scoped(const Scoped &) = delete;
    Scoped &operator=(const Scoped &) = delete;

    bool IsHandleValid(const _HandleType Handle) const { return Handle != _HandleType(-1) && Handle != nullptr; }

    void Close()
    {
        if (IsHandleValid(Handle_))
        {
            _Deleter()(Handle_);
            Handle_ = nullptr;
        }
    }

    bool Valid() const { return IsHandleValid(Handle_); }

    operator _HandleType() const { return Handle_; }
};

struct HandleDeleter_t
{
    void operator()(const HANDLE Handle) { CloseHandle(Handle); }
};
using ScopedHandle = Scoped<HANDLE, HandleDeleter_t>;

struct ServiceHandleDeleter_t
{
    void operator()(const SC_HANDLE &Handle) { CloseServiceHandle(Handle); };
};
using ScopedServiceHandle = Scoped<SC_HANDLE, ServiceHandleDeleter_t>;