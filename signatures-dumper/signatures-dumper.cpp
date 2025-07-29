#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <ctime>
#include <sstream>
#include "main_types.hpp"

#include "logx.hpp"
#include "process_util.hpp"
#include "module_util.hpp"
#include "pattern_util.hpp"
#include "offsets_writer.hpp"

using logx::g;
using logx::Level;

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

static std::string hex64(uint64_t v) { std::ostringstream o; o << "0x" << std::hex << std::uppercase << v; return o.str(); }
static std::string hex32(uint64_t v) { std::ostringstream o; o << "0x" << std::hex << std::uppercase << (uint32_t)v; return o.str(); }


std::vector<SigSpec> BuildSpecs() {
    std::vector<SigSpec> v;
    v.push_back({ "GlobalVars", {"client.dll","engine2.dll"}, {"48 89 15 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 48 85 D2"}, Resolve::RIP_ADDR, 3, 7, false });
    v.push_back({ "EntityList", {"client.dll"}, {"48 8B 0D ?? ?? ?? ?? 48 89 7C 24 ?? 8B FA C1 EB"}, Resolve::RIP_DEREF, 3, 7, false });
    v.push_back({ "ViewMatrix", {"client.dll"}, {"48 8D 0D ?? ?? ?? ?? 48 C1 E0 06"}, Resolve::RIP_ADDR, 3, 7, false });
    v.push_back({ "ViewAngles", {"client.dll"}, {"48 8B 0D ?? ?? ?? ?? E9 ?? ?? ?? ?? CC CC CC CC 40 55"}, Resolve::RIP_DEREF, 3, 7, true });
    v.push_back({ "LocalPlayerController", {"client.dll"}, {"48 8B 05 ?? ?? ?? ?? 48 85 C0 74 53"}, Resolve::RIP_DEREF, 3, 7, false });
    v.push_back({ "LocalPlayerPawn", {"client.dll"}, {"48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 88 ?? ?? 00 00"}, Resolve::RIP_DEREF, 3, 7, false });
    v.push_back({ "Prediction", {"client.dll"}, {"48 8D 05 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC 48 83 EC ?? 8B 0D"}, Resolve::RIP_ADDR, 3, 7, false });
    v.push_back({ "PlantedC4", {"client.dll"}, {"48 8B 15 ?? ?? ?? ?? FF C0 48 8D 4C 24 40"}, Resolve::RIP_DEREF, 3, 7, false });
    v.push_back({ "InventoryServices", {"client.dll"}, {"48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 90 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ??"}, Resolve::RIP_DEREF, 3, 7, false });
    return v;
}

static std::vector<Known> g_known = {
    {"EntityList",            0x1A05670},
    {"ViewMatrix",            0x1A6E3F0},
    {"LocalPlayerController", 0x1A53C38},
    {"ViewAngles",            0x1A78650},
    {"LocalPlayerPawn",       0x18590D0},
    {"GlobalVars",            0x184CEB0},
    {"PlantedC4",             0x1A72ED0}
};
static uint32_t get_known(const char* n) {
    for (const auto& k : g_known) if (!strcmp(k.name, n)) return k.rva;
    return 0;
}

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    g.init();
    g.banner();

   
    const wchar_t* procName = L"cs2.exe";
    std::wstring wname;
    if (argc >= 2) {
        wname.clear();
        for (const char* p = argv[1]; *p; ++p) wname.push_back((wchar_t)(unsigned char)*p);
        procName = wname.c_str();
    }

    DWORD pid = 0;
    if (!proc_util::GetPidByName(procName, pid)) {
        g.print(Level::ERR, "Процесс %ls не найден.", procName);
        return 1;
    }
    g.print(Level::GOOD, "PID: %lu", (unsigned long)pid);

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) {
        g.print(Level::ERR, "OpenProcess failed: %lu", GetLastError());
        return 1;
    }

    g.section("Сканирование модулей");
    std::vector<ModuleInfoEx> mods;
    if (!module_util::EnumModules(h, mods)) {
        g.print(Level::ERR, "EnumProcessModulesEx failed");
        CloseHandle(h);
        return 1;
    }
    for (const auto& m : mods)
        g.print(Level::TRACE, "%s base=%s size=0x%X", m.name.c_str(), hex64(m.base).c_str(), m.size);

    
    std::unordered_map<std::string, ModuleInfoEx> modmap;
    for (const auto& m : mods)
        modmap[to_lower(m.name)] = m;

   
    struct Buf {
        ModuleInfoEx mod;
        std::vector<uint8_t> bytes;
        std::vector<SectInfo> sects;
    };
    std::unordered_map<std::string, Buf> cache;

    auto get_buf = [&](const std::string& modName) -> Buf* {
        std::string key = to_lower(modName);
        auto it = cache.find(key);
        if (it != cache.end()) return &it->second;
        auto itM = modmap.find(key);
        if (itM == modmap.end()) return nullptr;
        Buf b;
        b.mod = itM->second;
        b.bytes.resize(b.mod.size);
        SIZE_T br = 0;
        if (!ReadProcessMemory(h, (LPCVOID)b.mod.base, b.bytes.data(), b.bytes.size(), &br) || br != b.bytes.size()) {
            g.print(Level::WARN, "RPM failed for %s", b.mod.name.c_str());
            return nullptr;
        }
        b.sects = module_util::ParseSections(b.bytes.data(), b.bytes.size(), b.mod.base);
        auto ins = cache.emplace(key, std::move(b));
        return &ins.first->second;
        };

  
    uint32_t buildNumber = 0;
    {
        auto it = modmap.find("engine2.dll");
        if (it != modmap.end()) {
            uint64_t addr = it->second.base + 0x540BE4;
            ReadProcessMemory(h, (LPCVOID)addr, &buildNumber, sizeof(buildNumber), nullptr);
        }
    }
    g.print(Level::INFO, "Build number (heuristic): %u", buildNumber);

    g.section("Поиск сигнатур");
    auto specs = BuildSpecs();
    std::vector<Found> results;
    results.reserve(specs.size());

    for (const auto& spec : specs) {
        g.print(Level::SCAN, "%s ...", spec.name.c_str());
        Found fe;
        fe.name = spec.name;
        fe.ok = false;
        fe.rva_instr = 0;
        fe.rva_addr = 0;
        fe.score = 0;

        for (const auto& modn : spec.modules) {
            Buf* buf = get_buf(modn);
            if (!buf) continue;
            const SectInfo* textSec = nullptr;
            for (const auto& s : buf->sects) if (s.is_text()) { textSec = &s; break; }
            for (const auto& patStr : spec.patterns) {
                if (patStr.empty()) continue;
                Pattern p;
                try { p = pattern_util::ParseIda(patStr); }
                catch (...) { continue; }
                size_t rva = pattern_util::FindPatternBMH(buf->bytes.data(), buf->bytes.size(), p);
                if (rva == SIZE_MAX) continue;
                fe.module = buf->mod.name;
                fe.base = buf->mod.base;
                fe.size = buf->mod.size;
                fe.pattern = patStr;
                fe.instr = buf->mod.base + rva;
                fe.rva_instr = (uint32_t)rva;
                int score = 50;
                if (textSec && textSec->contains(fe.instr)) score += 20;
                else fe.notes += "[instr !.text] ";
                if (spec.how == Resolve::NONE) {
                    fe.ok = true;
                }
                else {
                    int32_t disp = 0;
                    if (!pattern_util::ReadI32(h, fe.instr + spec.dispOff, disp)) {
                        fe.ok = false; fe.notes += "[disp read fail] ";
                        continue;
                    }
                    uint64_t tgt = pattern_util::RipTarget(fe.instr, disp, spec.instrLen);
                    fe.addr = tgt; fe.rva_addr = (uint32_t)(tgt - buf->mod.base);
                    if (spec.how == Resolve::RIP_DEREF) {
                        uint64_t q = 0;
                        if (pattern_util::ReadU64(h, tgt, q)) { fe.qword = q; score += 10; fe.ok = true; }
                        else { fe.ok = false; fe.notes += "[deref fail] "; }
                    }
                    else {
                        fe.ok = (tgt != 0);
                    }
                    if (fe.ok) {
                        bool inModule = (tgt >= buf->mod.base && tgt < buf->mod.base + buf->mod.size);
                        if (inModule) {
                            score += 15;
                            bool inData = false;
                            for (const auto& s : buf->sects)
                                if ((s.is_readable() || s.is_writable()) && !s.is_text() && s.contains(tgt))
                                {
                                    inData = true; break;
                                }
                            if (inData) score += 10;
                            else fe.notes += "[addr !data] ";
                        }
                        else fe.notes += "[addr !module] ";
                    }
                }
                if (fe.ok && spec.post_viewAngles_fix) {
                    if (fe.qword) {
                        uint64_t viewAbs = fe.qword + 0x3D0;
                        fe.addr = viewAbs;
                        if (viewAbs >= buf->mod.base && viewAbs < buf->mod.base + buf->mod.size)
                            fe.rva_addr = (uint32_t)(viewAbs - buf->mod.base);
                        else { fe.rva_addr = 0; fe.notes += "[angles out-of-module] "; }
                        score += 5;
                    }
                    else {
                        fe.notes += "[angles no base] ";
                    }
                }
                {
                    uint32_t k = get_known(spec.name.c_str());
                    if (k && fe.rva_addr == k) score += 10;
                }
                fe.score = std::clamp(score, 0, 100);
                break;
            }
            if (fe.ok) break;
        }
        if (!fe.ok) {
            uint32_t rva_known = get_known(spec.name.c_str());
            if (rva_known) {
                auto it = modmap.find("client.dll");
                if (it != modmap.end()) {
                    fe.module = it->second.name; fe.base = it->second.base; fe.size = it->second.size;
                    fe.addr = fe.base + rva_known; fe.rva_addr = rva_known; fe.ok = true;
                    fe.pattern = "<known>";
                    fe.score = 35; fe.notes += "[fallback known] ";
                }
            }
        }
        if (fe.ok) {
            g.print(Level::FOUND, "%-24s mod=%-12s rva=%s addr=%s  score=%d",
                fe.name.c_str(), fe.module.c_str(), hex32(fe.rva_addr).c_str(), hex64(fe.addr).c_str(), fe.score);
            if (!fe.notes.empty()) g.print(Level::DEBUG, "notes: %s", fe.notes.c_str());
        }
        else {
            g.print(Level::WARN, "%-24s NOT FOUND", fe.name.c_str());
        }
        results.push_back(std::move(fe));
    }

    g.section("Сохранение результатов");

    // dump_results.json
    offsets_writer::WriteJson("dump_results.json", pid, buildNumber, results);

    // generated_offsets.hpp
    offsets_writer::WriteHpp("generated_offsets.hpp", buildNumber, results);

 
    {
        std::ostringstream fn;
        fn << "offsets_" << buildNumber << ".json";
        offsets_writer::WriteJson(fn.str(), pid, buildNumber, results);
    }

    g.section("Готово");
    g.print(Level::GOOD, "Файлы: dump_results.json, generated_offsets.hpp, offsets_%u.json", buildNumber);

    CloseHandle(h);
    return 0;
}
