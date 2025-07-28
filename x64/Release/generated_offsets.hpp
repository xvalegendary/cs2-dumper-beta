#pragma once

// CS2 Mega Dumper (improved)
// Generated at 2025-07-28 13:27:27 UTC

#include <cstddef>

namespace cs2 {
namespace offsets {
    constexpr std::ptrdiff_t dwEntityList             = 0x1A05670;
    constexpr std::ptrdiff_t dwViewMatrix            = 0x1A6E3F0;
    constexpr std::ptrdiff_t dwViewAngles            = 0x1A78650;
    constexpr std::ptrdiff_t dwLocalPlayerController = 0x1A53C38;
    constexpr std::ptrdiff_t dwLocalPlayerPawn       = 0x18590D0;
    constexpr std::ptrdiff_t dwGlobalVars            = 0x184CEB0;
    constexpr std::ptrdiff_t dwPlantedC4             = 0x1A72ED0;
}

namespace signatures {
    inline const char* GlobalVars = "<known>";
    inline const char* EntityList = "48 8B 0D ?? ?? ?? ?? 48 89 7C 24 ?? 8B FA C1 EB";
    inline const char* ViewMatrix = "48 8D 0D ?? ?? ?? ?? 48 C1 E0 06";
    inline const char* ViewAngles = "48 8B 0D ?? ?? ?? ?? E9 ?? ?? ?? ?? CC CC CC CC 40 55";
    inline const char* LocalPlayerController = "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 53";
    inline const char* LocalPlayerPawn = "<known>";
    inline const char* PlantedC4 = "<known>";
    inline const char* InventoryServices = "48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 90 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ??";
}

} // namespace cs2
