// Axel '0vercl0k' Souchet - February 22 2020
#pragma once
#include <windows.h>
#include <tchar.h>

bool
InstallDriver(const TCHAR *ServiceName, const TCHAR *ServiceDisplayName, const TCHAR *ServiceFilename);

bool
StartDriver(const TCHAR *ServiceName);

bool
StopDriver(const TCHAR *ServiceName);

bool
RemoveDriver(const TCHAR *ServiceName);