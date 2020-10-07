// Axel '0vercl0k' Souchet - October 6 2020
#pragma once
#include "../common/common.h"
#include <cstdint>
#include <string>
#include <unordered_map>

//
// Grabs a list of the running processes.
//

std::unordered_map<uintptr_t, std::string> GetProcessList();

//
// Populates the offsets the driver needs to work.
//

bool GetOffsets(SIC_OFFSETS &SicOffsets);