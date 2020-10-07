# Sharing is Caring - Enumerate usermode shared memory mappings on Windows
![Builds](https://github.com/0vercl0k/sic/workflows/Builds/badge.svg)

## Overview

This utility enumerates the various shared memory regions mapped in Windows processes. SiC leverages a Windows driver and the [dbghelp]() API to scan the running processes and find the said regions.

Special thanks to [@masthoon](https://github.com/masthoon) for suggesting the idea and [@yrp604](https://github.com/yrp604) for numerous discussions on virtual memory management.

## Usage

In order for SiC to work you need to place `dbghelp.dll` as well as `symsrv.dll` in the directory of the SiC executable. Sic attempts to copy the two files if they are found in the default Windows SDK's Debuggers install location: `c:\Program Files (x86)\Windows Kits\10\Debuggers\<arch>`.

SiC installs a driver in order to be able to scan processes [Virtual Address Descriptors](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-vad) which are software constructs defined by the Windows' kernel to describe a virtual memory region.

```
SiC - Enumerate shared memory mappings on Windows
Usage: src\x64\Release\sic.exe [OPTIONS]

Options:
  -h,--help                   Print this help message and exit
  --help-all                  Expand all help
  -f,--filer TEXT             Only display shms owned by processes matching this filter
```

The provided driver is [test-signed](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/how-to-test-sign-a-driver-package) and as a result you need to turn on [test-signing](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option) in your VM in order to be able to run the driver (`bcdedit.exe -set testsigning on`).

The driver has been tested on the following platforms:

:white_check_mark: Windows 10 1903 x64

If you have successfully run it on a different platform, please let me know and I will update the list. If you encounterered any issues running it, please file an issue and I will be happy to help / fix the issue.

## How?

The first thing the SiC driver does is to enumerate processes running on the system. Once it has a list of processes, it iterates through it and visit the VAD tree of each process.

When it finds a VAD that refers to a [Prototype PTE](https://www.codemachine.com/article_protopte.html) it keeps track of the PTE as well as which process has it mapped in its address space.

Once the driver is done scanning all the VAD trees, it basically has built a lookup table that contains every Prototype PTEs and a list of processes that have mapped it in their address spaces. The table is packed and sent to user mode where the user agent can display the information.

## Build

You can open the Visual Studio solution `sic.sln` or build it via the command line with:

```
(base) sic>msbuild /p:Configuration=Release src\sic.sln
Microsoft (R) Build Engine version 16.7.0+b89cb5fde for .NET Framework
Copyright (C) Microsoft Corporation. All rights reserved.

[...]

Build succeeded.
    0 Warning(s)
    0 Error(s)

Time Elapsed 00:00:00.42
```