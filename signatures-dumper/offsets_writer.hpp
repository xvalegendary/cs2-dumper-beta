#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "main_types.hpp"

namespace offsets_writer {
    void WriteJson(const std::string& filename, uint32_t pid, uint32_t buildNumber, const std::vector<Found>& results);
    void WriteHpp(const std::string& filename, uint32_t buildNumber, const std::vector<Found>& results);
}
