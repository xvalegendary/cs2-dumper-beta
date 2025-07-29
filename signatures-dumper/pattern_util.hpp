#pragma once
#include <cstdint>
#include <vector>
#include "main_types.hpp"
#include <string>


namespace pattern_util {
    Pattern ParseIda(const std::string& ida);
    size_t FindPatternBMH(const uint8_t* data, size_t size, const Pattern& p);
    bool ReadU64(HANDLE h, uint64_t addr, uint64_t& out);
    bool ReadI32(HANDLE h, uint64_t addr, int32_t& out);
    uint64_t RipTarget(uint64_t instrAbs, int32_t disp, int instrLen);
}
