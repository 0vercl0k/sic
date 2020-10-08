// Axel '0vercl0k' Souchet - February 22 2020
#pragma once
#include <windows.h>

//
// Installs the driver as a service.
//

bool InstallDriver(const char *ServiceName, const char *ServiceDisplayName,
                   const char *ServiceFilename);

//
// Starts up the driver.
//

bool StartDriver(const char *ServiceName);

//
// Stops the driver.
//

bool StopDriver(const char *ServiceName);

//
// Removes the driver off the system.
//

bool RemoveDriver(const char *ServiceName);