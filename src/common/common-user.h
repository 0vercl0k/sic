// Axel '0vercl0k' Souchet - February 20 2020
#pragma once

#include <windows.h>

//
// Ghetto version of base::win::ScopedHandle:
// https://cs.chromium.org/chromium/buildtools/gn/src/base/win/scoped_handle.h
//

template <typename HandleTy, typename DeleterTy>
class Scoped_t
{
private:
    HandleTy Handle_;

public:
    Scoped_t(const HandleTy Handle) : Handle_(Handle) {}

    //
    // Rule of three.
    //

    ~Scoped_t() { Close(); }
    Scoped_t(const Scoped_t &) = delete;
    Scoped_t &operator=(const Scoped_t &) = delete;

    bool IsHandleValid(const HandleTy Handle) const { return Handle != HandleTy(-1) && Handle != nullptr; }

    void Close()
    {
        if (IsHandleValid(Handle_))
        {
            DeleterTy::Close(Handle_);
            Handle_ = nullptr;
        }
    }

    bool Valid() const { return IsHandleValid(Handle_); }

    operator HandleTy() const { return Handle_; }

};

struct HandleDeleter_t
{
    static void Close(const HANDLE Handle) { CloseHandle(Handle); }
};

struct ServiceHandleDeleter_t
{
    static void Close(const SC_HANDLE &Handle) { CloseServiceHandle(Handle); };
};

//
// Handy types for cleaning up the code.
//

using ScopedHandle_t = Scoped_t<HANDLE, HandleDeleter_t>;
using ScopedServiceHandle_t = Scoped_t<SC_HANDLE, ServiceHandleDeleter_t>;

//
// Simple RAII class to execute a function on a scope end.
//

template <typename ExitFunctionTy>
class ScopeExit_t
{
    ExitFunctionTy ExitFunction_;

public:
    explicit ScopeExit_t(ExitFunctionTy &&ExitFunction) : ExitFunction_(ExitFunction) {}

    //
    // Rule of three.
    //

    ~ScopeExit_t() { ExitFunction_(); }
    ScopeExit_t(const ScopeExit_t &) = delete;
    ScopeExit_t &operator=(const ScopeExit_t &) = delete;
};
