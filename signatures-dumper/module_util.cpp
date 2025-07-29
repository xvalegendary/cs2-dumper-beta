#include "module_util.hpp"
#include <psapi.h>
#include <winnt.h>
#include <algorithm>
#include "process_util.hpp"
#include "main_types.hpp" 

namespace module_util {

    bool EnumModules(HANDLE h, std::vector<ModuleInfoEx>& out) {
        HMODULE mods[4096]; DWORD need = 0;
        if (!EnumProcessModulesEx(h, mods, sizeof(mods), &need, LIST_MODULES_ALL)) return false;
        size_t n = need / sizeof(HMODULE); out.reserve(n);
        wchar_t nameW[MAX_PATH]; wchar_t pathW[MAX_PATH]; MODULEINFO mi{};
        for (size_t i = 0; i < n; ++i) {
            if (!GetModuleInformation(h, mods[i], &mi, sizeof(mi))) continue;
            if (!GetModuleBaseNameW(h, mods[i], nameW, MAX_PATH)) continue;
            if (!GetModuleFileNameExW(h, mods[i], pathW, MAX_PATH)) continue;
            ModuleInfoEx m; m.hMod = mods[i]; m.base = (uint64_t)mi.lpBaseOfDll; m.size = (uint32_t)mi.SizeOfImage;
            std::wstring nws(nameW); std::wstring pws(pathW);
            m.name = proc_util::WstrToUtf8(nws);
            m.path = proc_util::WstrToUtf8(pws);
            std::transform(m.name.begin(), m.name.end(), m.name.begin(), ::tolower);
            out.push_back(std::move(m));
        }
        return true;
    }

    std::vector<SectInfo> ParseSections(const uint8_t* img, size_t size, uint64_t base) {
        std::vector<SectInfo> v;
        if (size < sizeof(IMAGE_DOS_HEADER)) return v;
        const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)img;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return v;
        if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > size) return v;
        const IMAGE_NT_HEADERS64* nt = (const IMAGE_NT_HEADERS64*)(img + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return v;
        const IMAGE_SECTION_HEADER* sh = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            const auto& s = sh[i];
            char name[9]{}; memcpy(name, s.Name, 8);
            uint64_t va = base + s.VirtualAddress;
            uint64_t vsz = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
            if (!vsz) continue;
            SectInfo si; si.name = name; si.start = va; si.end = va + vsz; si.characteristics = s.Characteristics;
            v.push_back(std::move(si));
        }
        return v;
    }

} // namespace module_util
