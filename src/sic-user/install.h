// Axel '0vercl0k' Souchet - February 22 2020
#pragma once
#include <windows.h>

bool InstallDriver(const char *ServiceName, const char *ServiceDisplayName,
                   const char *ServiceFilename);

bool StartDriver(const char *ServiceName);

bool StopDriver(const char *ServiceName);

bool RemoveDriver(const char *ServiceName);