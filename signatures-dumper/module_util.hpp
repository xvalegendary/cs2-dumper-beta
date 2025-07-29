#pragma once
#include <windows.h>
#include <vector>
#include "main_types.hpp"

namespace module_util {
    bool EnumModules(HANDLE h, std::vector<ModuleInfoEx>& out);
    std::vector<SectInfo> ParseSections(const uint8_t* img, size_t size, uint64_t base);
}
