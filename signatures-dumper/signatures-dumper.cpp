#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winnt.h>

#include <cstdint>
#include <cstdio>
#include <cinttypes>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <mutex>
#include <cstdarg>

#pragma comment(lib, "Psapi.lib")



namespace logx {

    enum class Level { TRACE, DEBUG, INFO, GOOD, WARN, ERR, SCAN, FOUND, SECTION };

    struct Logger {
        HANDLE hOut{ GetStdHandle(STD_OUTPUT_HANDLE) };
        bool vt{ false };
        WORD baseAttrs{ 0 };
        std::mutex mtx;

        
        static constexpr const char* ESC = "\x1b[";
        static constexpr const char* RESET = "\x1b[0m";
        static constexpr const char* BOLD = "\x1b[1m";

       
        static std::string rgb(int r, int g, int b) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "\x1b[38;2;%d;%d;%dm", r, g, b);
            return buf;
        }
        static std::string bgr(int r, int g, int b) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "\x1b[48;2;%d;%d;%dm", r, g, b);
            return buf;
        }

        bool enable_vt() {
            DWORD mode = 0;
            if (!GetConsoleMode(hOut, &mode)) return false;
            DWORD want = mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT;
            if (!SetConsoleMode(hOut, want)) return false;
            vt = true; return true;
        }

        void init() {
            CONSOLE_SCREEN_BUFFER_INFO ci{};
            if (GetConsoleScreenBufferInfo(hOut, &ci)) baseAttrs = ci.wAttributes;
            vt = enable_vt(); 
        }

        static std::string now_time() {
            SYSTEMTIME st; GetLocalTime(&st);
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%02u:%02u:%02u", st.wHour, st.wMinute, st.wSecond);
            return buf;
        }

        static const char* icon(Level lv) {
            switch (lv) {
            case Level::GOOD:   return "✔";
            case Level::INFO:   return "ℹ";
            case Level::WARN:   return "⚠";
            case Level::ERR:    return "✖";
            case Level::SCAN:   return "🔎";
            case Level::FOUND:  return "✅";
            case Level::SECTION:return "◆";
            case Level::TRACE:  return "·";
            case Level::DEBUG:  return "◼";
            default: return "•";
            }
        }

        struct Style { std::string fg; WORD attr; };

        Style style(Level lv) const {
            if (!vt) {
                
                switch (lv) {
                case Level::GOOD:   return { "", FOREGROUND_GREEN | FOREGROUND_INTENSITY };
                case Level::INFO:   return { "", FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY };
                case Level::WARN:   return { "", FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY };
                case Level::ERR:    return { "", FOREGROUND_RED | FOREGROUND_INTENSITY };
                case Level::SCAN:   return { "", FOREGROUND_BLUE | FOREGROUND_INTENSITY };
                case Level::FOUND:  return { "", FOREGROUND_GREEN | FOREGROUND_INTENSITY };
                case Level::SECTION:return { "", FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY };
                case Level::DEBUG:  return { "", FOREGROUND_BLUE | FOREGROUND_GREEN };
                case Level::TRACE:  return { "", FOREGROUND_BLUE };
                default:            return { "", baseAttrs };
                }
            }
            else {
                // насыщённые 24-битные
                switch (lv) {
                case Level::GOOD:   return { rgb(67, 201,  76), 0 };
                case Level::INFO:   return { rgb(96, 181, 255), 0 };
                case Level::WARN:   return { rgb(255, 191,  64), 0 };
                case Level::ERR:    return { rgb(255,  92,  92), 0 };
                case Level::SCAN:   return { rgb(179, 128, 255), 0 };
                case Level::FOUND:  return { rgb(102, 255, 153), 0 };
                case Level::SECTION:return { rgb(255, 128, 255), 0 };
                case Level::DEBUG:  return { rgb(160, 160, 160), 0 };
                case Level::TRACE:  return { rgb(120, 120, 120), 0 };
                default:            return { rgb(200, 200, 200), 0 };
                }
            }
        }

        void vprint(Level lv, const char* fmt, va_list ap) {
            char msg[4096];
            std::vsnprintf(msg, sizeof(msg), fmt, ap);

            std::lock_guard<std::mutex> lk(mtx);

            std::string t = now_time();
            const char* ic = icon(lv);
            Style st = style(lv);

            if (vt) {
                std::string line;
                line.reserve(512 + strlen(msg));
                
                std::string tag;
                switch (lv) {
                case Level::GOOD: tag = "OK"; break;
                case Level::INFO: tag = "INFO"; break;
                case Level::WARN: tag = "WARN"; break;
                case Level::ERR:  tag = "ERR"; break;
                case Level::SCAN: tag = "SCAN"; break;
                case Level::FOUND:tag = "FOUND"; break;
                case Level::SECTION: tag = "SECTION"; break;
                case Level::DEBUG: tag = "DBG"; break;
                case Level::TRACE: tag = "TRC"; break;
                default: tag = "LOG";
                }
                line += rgb(120, 120, 120) + "[" + t + "] " + RESET;
                line += st.fg + BOLD + ic + " " + tag + RESET + " ";
                line += st.fg + msg + RESET;
                line += "\n";
                DWORD bw; WriteConsoleA(hOut, line.c_str(), (DWORD)line.size(), &bw, nullptr);
            }
            else {
               
                DWORD bw;
                std::ostringstream oss;
                oss << "[" << t << "] " << ic << " ";
                auto s = oss.str();
                SetConsoleTextAttribute(hOut, baseAttrs);
                WriteConsoleA(hOut, s.c_str(), (DWORD)s.size(), &bw, nullptr);
                SetConsoleTextAttribute(hOut, st.attr);
                WriteConsoleA(hOut, msg, (DWORD)strlen(msg), &bw, nullptr);
                WriteConsoleA(hOut, "\n", 1, &bw, nullptr);
                SetConsoleTextAttribute(hOut, baseAttrs);
            }
        }

        void print(Level lv, const char* fmt, ...) {
            va_list ap; va_start(ap, fmt); vprint(lv, fmt, ap); va_end(ap);
        }

        void banner() {
            std::lock_guard<std::mutex> lk(mtx);
            if (vt) {
                auto c1 = rgb(255, 99, 132);
                auto c2 = rgb(255, 159, 64);
                auto c3 = rgb(255, 205, 86);
                auto c4 = rgb(75, 192, 192);
                auto c5 = rgb(54, 162, 235);
                auto c6 = rgb(153, 102, 255);
                std::string line1 = c6 + "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓" + RESET + "\n";
                std::string line2 = c5 + "┃ " + c1 + "CS2 Dumper" + c5 + " — " + c2 + c5 + ", " + c3 + "heuristics" + c5 + ", " + c4 + "sections" + c5 + " ┃" + RESET + "\n";
                std::string line3 = c6 + "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛" + RESET + "\n";

                DWORD bw;
                WriteConsoleA(hOut, line1.c_str(), (DWORD)line1.size(), &bw, nullptr);
                WriteConsoleA(hOut, line2.c_str(), (DWORD)line2.size(), &bw, nullptr);
                WriteConsoleA(hOut, line3.c_str(), (DWORD)line3.size(), &bw, nullptr);
            }
            else {
                DWORD bw; const char* t =
                    "==================== CS2  Dumper ====================\n";
                WriteConsoleA(hOut, t, (DWORD)strlen(t), &bw, nullptr);
            }
        }

        void section(const char* title) {
            if (vt) {
                auto bar = rgb(100, 100, 255);
                auto ttl = rgb(255, 170, 255);
                print(Level::SECTION, "%s%s%s", bar.c_str(), title, RESET);
            }
            else {
                print(Level::SECTION, "%s", title);
            }
        }
    };

    static Logger g;

} // namespace logx

using logx::g;
using logx::Level;



static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}
static std::string hex64(uint64_t v) { std::ostringstream o; o << "0x" << std::hex << std::uppercase << v; return o.str(); }
static std::string hex32(uint64_t v) { std::ostringstream o; o << "0x" << std::hex << std::uppercase << (uint32_t)v; return o.str(); }

struct ModuleInfoEx {
    HMODULE  hMod{};
    uint64_t base{};
    uint32_t size{};
    std::string name; // lowercase
    std::string path; 
};

static bool GetPidByName(const wchar_t* name, DWORD& pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe{ sizeof(pe) }; bool ok = false;
    if (Process32FirstW(hSnap, &pe)) {
        do { if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; ok = true; break; } } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap); return ok;
}

static std::string WstrToUtf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    std::string out(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), out.data(), len, nullptr, nullptr); return out;
}

static bool EnumModules(HANDLE h, std::vector<ModuleInfoEx>& out) {
    HMODULE mods[4096]; DWORD need = 0;
    if (!EnumProcessModulesEx(h, mods, sizeof(mods), &need, LIST_MODULES_ALL)) return false;
    size_t n = need / sizeof(HMODULE); out.reserve(n);
    wchar_t nameW[MAX_PATH]; wchar_t pathW[MAX_PATH]; MODULEINFO mi{};
    for (size_t i = 0;i < n;++i) {
        if (!GetModuleInformation(h, mods[i], &mi, sizeof(mi))) continue;
        if (!GetModuleBaseNameW(h, mods[i], nameW, MAX_PATH)) continue;
        if (!GetModuleFileNameExW(h, mods[i], pathW, MAX_PATH)) continue;
        ModuleInfoEx m; m.hMod = mods[i]; m.base = (uint64_t)mi.lpBaseOfDll; m.size = (uint32_t)mi.SizeOfImage;
        std::wstring nws(nameW); std::wstring pws(pathW);
        m.name = to_lower(WstrToUtf8(nws)); m.path = WstrToUtf8(pws);
        out.push_back(std::move(m));
    }
    return true;
}


struct SectInfo {
    std::string name;
    uint64_t start{};
    uint64_t end{};
    DWORD characteristics{};
    bool contains(uint64_t addr) const { return addr >= start && addr < end; }
    bool is_text() const { return (characteristics & IMAGE_SCN_CNT_CODE) != 0; }
    bool is_readable() const { return (characteristics & IMAGE_SCN_MEM_READ) != 0; }
    bool is_writable() const { return (characteristics & IMAGE_SCN_MEM_WRITE) != 0; }
};

static std::vector<SectInfo> ParseSections(const uint8_t* img, size_t size, uint64_t base) {
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

static const SectInfo* find_text(const std::vector<SectInfo>& v) {
    for (auto& s : v) if (s.is_text()) return &s; return nullptr;
}
static bool in_readable_data(const std::vector<SectInfo>& v, uint64_t addr) {
    for (auto& s : v) {
        if ((s.is_readable() || s.is_writable()) && !s.is_text())
            if (s.contains(addr)) return true;
    }
    return false;
}


struct Pattern { std::vector<uint8_t> b; std::vector<uint8_t> m; /*0=wild,1=cmp*/ };

static Pattern ParseIda(const std::string& ida) {
    Pattern p; std::istringstream iss(ida); std::string tok;
    while (iss >> tok) {
        if (tok == "?" || tok == "??") { p.b.push_back(0); p.m.push_back(0); }
        else {
            if (tok.size() > 2) throw std::runtime_error("bad byte token: " + tok);
            uint8_t v = (uint8_t)strtoul(tok.c_str(), nullptr, 16); p.b.push_back(v); p.m.push_back(1);
        }
    }
    return p;
}


static size_t FindPatternBMH(const uint8_t* data, size_t size, const Pattern& p) {
    const size_t n = p.b.size(); if (!n || size < n) return SIZE_MAX;
    int anchor = -1; for (int i = (int)n - 1; i >= 0; --i) { if (p.m[i]) { anchor = i; break; } }
    if (anchor < 0) return 0;

    uint8_t ach = p.b[(size_t)anchor];
    size_t i = anchor;
    while (i < size) {
        while (i < size && data[i] != ach) i++;
        if (i >= size) break;
        size_t start = i - anchor; if (start + n > size) { i++; continue; }
        bool ok = true;
        for (size_t j = 0; j < n; ++j) { if (p.m[j] && data[start + j] != p.b[j]) { ok = false; break; } }
        if (ok) return start;
        i++;
    }
    return SIZE_MAX;
}


static bool ReadU64(HANDLE h, uint64_t addr, uint64_t& out) { SIZE_T br = 0; if (!ReadProcessMemory(h, (LPCVOID)addr, &out, sizeof(out), &br)) return false; return br == sizeof(out); }
static bool ReadI32(HANDLE h, uint64_t addr, int32_t& out) { SIZE_T br = 0; if (!ReadProcessMemory(h, (LPCVOID)addr, &out, sizeof(out), &br)) return false; return br == sizeof(out); }
static uint64_t RipTarget(uint64_t instrAbs, int32_t disp, int instrLen) { return instrAbs + instrLen + (int64_t)disp; }

enum class Resolve { NONE, RIP_ADDR, RIP_DEREF };

struct SigSpec {
    std::string name;
    std::vector<std::string> modules;     
    std::vector<std::string> patterns;    
    Resolve how{ Resolve::NONE };
    int dispOff{ 3 };
    int instrLen{ 7 };
    bool post_viewAngles_fix{ false };    // ViewAngles = *(CSGOInput) + 0x3D0
};

struct Found {
    std::string name;
    std::string module;
    std::string pattern;
    uint64_t base{};    
    uint64_t size{};    
    uint64_t instr{};   
    uint64_t addr{};    
    uint64_t qword{};   // deref value if RIP_DEREF
    uint32_t rva_instr{};
    uint32_t rva_addr{};
    bool ok{};
    int score{};        
    std::string notes;  
};


static std::vector<SigSpec> BuildSpecs() {
    std::vector<SigSpec> v;

    v.push_back({
        "GlobalVars",
        {"client.dll","engine2.dll"},
        {
            "48 89 15 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 48 85 D2",
            "48 8B 05 ?? ?? ?? ?? F3 0F 10 40 48",
            "48 8B 0D ?? ?? ?? ?? 44 0F 28 C1",
            "48 89 0D ?? ?? ?? ?? 48 89 41"
        },
        Resolve::RIP_ADDR, 3, 7, false
        });

    v.push_back({
        "EntityList",
        {"client.dll"},
        {"48 8B 0D ?? ?? ?? ?? 48 89 7C 24 ?? 8B FA C1 EB"},
        Resolve::RIP_DEREF,3,7,false
        });

    v.push_back({
        "ViewMatrix",
        {"client.dll"},
        {"48 8D 0D ?? ?? ?? ?? 48 C1 E0 06"},
        Resolve::RIP_ADDR,3,7,false
        });

    v.push_back({
        "ViewAngles",
        {"client.dll"},
        {"48 8B 0D ?? ?? ?? ?? E9 ?? ?? ?? ?? CC CC CC CC 40 55"},
        Resolve::RIP_DEREF,3,7,true
        });

    v.push_back({
        "LocalPlayerController",
        {"client.dll"},
        {
            "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 53",
            "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 8B 88"
        },
        Resolve::RIP_DEREF,3,7,false
        });

    v.push_back({
        "LocalPlayerPawn",
        {"client.dll"},
        {
            "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 88 ?? ?? 00 00",
            "48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 81 ?? ?? 00 00"
        },
        Resolve::RIP_DEREF,3,7,false
        });

    v.push_back({
        "Prediction",
        {"client.dll"},
        {"48 8D 05 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC 48 83 EC ?? 8B 0D"},
        Resolve::RIP_ADDR,3,7,false
        });

    v.push_back({
        "PlantedC4",
        {"client.dll"},
        {"48 8B 15 ?? ?? ?? ?? FF C0 48 8D 4C 24 40"},
        Resolve::RIP_DEREF,3,7,false
        });

    v.push_back({
        "InventoryServices",
        {"client.dll"},
        {"48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 90 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ??"},
        Resolve::RIP_DEREF,3,7,false
        });

    return v;
}


struct Known { const char* name; uint32_t rva; };
static std::vector<Known> g_known = {
    {"EntityList",            0x1A05670},
    {"ViewMatrix",            0x1A6E3F0},
    {"LocalPlayerController", 0x1A53C38},
    {"ViewAngles",            0x1A78650}, // derived (CSGOInput+0x3D0)
    {"LocalPlayerPawn",       0x18590D0},
    {"GlobalVars",            0x184CEB0},
    {"PlantedC4",             0x1A72ED0}
};
static uint32_t get_known(const char* n) {
    for (auto& k : g_known) if (!strcmp(k.name, n)) return k.rva; return 0;
}


int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    g.init();
    g.banner();

    const wchar_t* procName = L"cs2.exe";
    if (argc >= 2) {
        static std::wstring w; w.clear();
        for (const char* p = argv[1]; *p; ++p) w.push_back((wchar_t)(unsigned char)*p);
        procName = w.c_str();
    }

    DWORD pid = 0;
    if (!GetPidByName(procName, pid)) {
        g.print(Level::ERR, "Процесс %ls не найден.", procName);
        return 1;
    }
    g.print(Level::GOOD, "PID: %lu", (unsigned long)pid);

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) { g.print(Level::ERR, "OpenProcess failed: %lu", GetLastError()); return 1; }

    g.section("Сканирование модулей");
    std::vector<ModuleInfoEx> mods;
    if (!EnumModules(h, mods)) { g.print(Level::ERR, "EnumProcessModulesEx failed"); CloseHandle(h); return 1; }
    for (auto& m : mods) g.print(Level::TRACE, "%s base=%s size=0x%X", m.name.c_str(), hex64(m.base).c_str(), m.size);

    std::unordered_map<std::string, ModuleInfoEx> modmap; for (auto& m : mods) modmap[m.name] = m;

    struct Buf { ModuleInfoEx mod; std::vector<uint8_t> bytes; std::vector<SectInfo> sects; };
    std::unordered_map<std::string, Buf> cache;

    auto get_buf = [&](const std::string& modName)->Buf* {
        std::string key = to_lower(modName);
        auto it = cache.find(key); if (it != cache.end()) return &it->second;
        auto itM = modmap.find(key); if (itM == modmap.end()) return nullptr;
        Buf b; b.mod = itM->second; b.bytes.resize(b.mod.size);
        SIZE_T br = 0;
        if (!ReadProcessMemory(h, (LPCVOID)b.mod.base, b.bytes.data(), b.bytes.size(), &br) || br != b.bytes.size()) {
            g.print(Level::WARN, "RPM failed for %s", b.mod.name.c_str()); return nullptr;
        }
        b.sects = ParseSections(b.bytes.data(), b.bytes.size(), b.mod.base);
        auto ins = cache.emplace(key, std::move(b)); return &ins.first->second;
        };

    auto specs = BuildSpecs();
    std::vector<Found> results; results.reserve(specs.size());

  
    uint32_t buildNumber = 0;
    {
        auto it = modmap.find("engine2.dll");
        if (it != modmap.end()) {
            uint64_t addr = it->second.base + 0x540BE4; // эвристика
            ReadProcessMemory(h, (LPCVOID)addr, &buildNumber, sizeof(buildNumber), nullptr);
        }
    }
    g.print(Level::INFO, "Build number (heuristic): %u", buildNumber);

    g.section("Поиск сигнатур");
    for (const auto& spec : specs) {
        g.print(Level::SCAN, "%s ...", spec.name.c_str());
        Found fe; fe.name = spec.name; fe.ok = false; fe.rva_instr = 0; fe.rva_addr = 0; fe.score = 0;

        for (const auto& modn : spec.modules) {
            Buf* buf = get_buf(modn); if (!buf) continue;

            const SectInfo* textSec = find_text(buf->sects);

            for (const auto& patStr : spec.patterns) {
                if (patStr.empty()) continue;
                Pattern p; try { p = ParseIda(patStr); }
                catch (...) { continue; }

                size_t rva = FindPatternBMH(buf->bytes.data(), buf->bytes.size(), p);
                if (rva == SIZE_MAX) continue;

                fe.module = buf->mod.name; fe.base = buf->mod.base; fe.size = buf->mod.size;
                fe.pattern = patStr; fe.instr = buf->mod.base + rva; fe.rva_instr = (uint32_t)rva;

                int score = 50;

                if (textSec && textSec->contains(fe.instr)) score += 20;
                else fe.notes += "[instr !.text] ";

                if (spec.how == Resolve::NONE) { fe.ok = true; }
                else {
                    int32_t disp = 0; if (!ReadI32(h, fe.instr + spec.dispOff, disp)) {
                        fe.ok = false; fe.notes += "[disp read fail] ";
                        continue;
                    }
                    uint64_t tgt = RipTarget(fe.instr, disp, spec.instrLen);
                    fe.addr = tgt; fe.rva_addr = (uint32_t)(tgt - buf->mod.base);

                    if (spec.how == Resolve::RIP_DEREF) {
                        uint64_t q = 0;
                        if (ReadU64(h, tgt, q)) { fe.qword = q; score += 10; fe.ok = true; }
                        else { fe.ok = false; fe.notes += "[deref fail] "; }
                    }
                    else {
                        fe.ok = (tgt != 0);
                    }

                    if (fe.ok) {
                        bool inModule = (tgt >= buf->mod.base && tgt < buf->mod.base + buf->mod.size);
                        if (inModule) {
                            score += 15;
                            if (in_readable_data(buf->sects, tgt)) score += 10;
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
    {
        std::ofstream js("dump_results.json", std::ios::binary);
        js << "{\n";
        js << "  \"pid\": " << pid << ",\n";
        js << "  \"buildNumber\": " << buildNumber << ",\n";
        js << "  \"results\": [\n";
        for (size_t i = 0;i < results.size();++i) {
            const auto& e = results[i];
            js << "    {\n";
            js << "      \"name\": \"" << e.name << "\",\n";
            js << "      \"module\": \"" << e.module << "\",\n";
            js << "      \"pattern\": \"" << e.pattern << "\",\n";
            js << "      \"rva_instr\": \"" << hex32(e.rva_instr) << "\",\n";
            js << "      \"rva_addr\": \"" << hex32(e.rva_addr) << "\",\n";
            js << "      \"instr\": \"" << hex64(e.instr) << "\",\n";
            js << "      \"addr\": \"" << hex64(e.addr) << "\",\n";
            js << "      \"qword\": \"" << hex64(e.qword) << "\",\n";
            js << "      \"ok\": " << (e.ok ? "true" : "false") << ",\n";
            js << "      \"score\": " << e.score << ",\n";
            js << "      \"notes\": \"" << e.notes << "\"\n";
            js << "    }" << (i + 1 == results.size() ? "\n" : ",\n");
        }
        js << "  ]\n";
        js << "}\n";
        js.close();
        g.print(Level::GOOD, "dump_results.json — OK");
    }

    auto get_rva = [&](const char* n)->uint32_t {
        for (auto& e : results) if (e.name == n && e.ok) return e.rva_addr; return 0;
        };

    uint32_t rva_entity = get_rva("EntityList");
    uint32_t rva_matrix = get_rva("ViewMatrix");
    uint32_t rva_angles = get_rva("ViewAngles");
    uint32_t rva_lpc = get_rva("LocalPlayerController");
    uint32_t rva_lpp = get_rva("LocalPlayerPawn"); if (!rva_lpp) rva_lpp = get_known("LocalPlayerPawn");
    uint32_t rva_gvars = get_rva("GlobalVars");
    uint32_t rva_c4 = get_rva("PlantedC4");

  
    std::time_t t = std::time(nullptr); std::tm tm{}; gmtime_s(&tm, &t);
    char timebuf[64]; std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S UTC", &tm);

    {
        std::ofstream hh("generated_offsets.hpp", std::ios::binary);
        hh << "#pragma once\n\n";
        hh << "// CS2 Dumper (beta)\n";
        hh << "// Generated at " << timebuf << "\n\n";
        hh << "#include <cstddef>\n\n";
        hh << "namespace cs2 {\n";
        hh << "namespace offsets {\n";
        if (rva_entity) hh << "    constexpr std::ptrdiff_t dwEntityList             = 0x" << std::hex << std::uppercase << rva_entity << ";\n";
        if (rva_matrix) hh << "    constexpr std::ptrdiff_t dwViewMatrix            = 0x" << std::hex << std::uppercase << rva_matrix << ";\n";
        if (rva_angles) hh << "    constexpr std::ptrdiff_t dwViewAngles            = 0x" << std::hex << std::uppercase << rva_angles << ";\n";
        if (rva_lpc)    hh << "    constexpr std::ptrdiff_t dwLocalPlayerController = 0x" << std::hex << std::uppercase << rva_lpc << ";\n";
        if (rva_lpp)    hh << "    constexpr std::ptrdiff_t dwLocalPlayerPawn       = 0x" << std::hex << std::uppercase << rva_lpp << ";\n";
        if (rva_gvars)  hh << "    constexpr std::ptrdiff_t dwGlobalVars            = 0x" << std::hex << std::uppercase << rva_gvars << ";\n";
        if (rva_c4)     hh << "    constexpr std::ptrdiff_t dwPlantedC4             = 0x" << std::hex << std::uppercase << rva_c4 << ";\n";
        hh << "}\n\n";
        hh << "namespace signatures {\n";
        auto emit = [&](const char* name, const std::vector<SigSpec>& specs, const std::vector<Found>& results) {
            const SigSpec* sp = nullptr; for (auto& s : specs) if (s.name == name) { sp = &s; break; }
            std::string pat;
            for (auto& e : results) if (e.name == name && e.ok) { pat = e.pattern; break; }
            if (pat.empty() && sp && !sp->patterns.empty()) pat = sp->patterns.front();
            if (pat.empty()) pat = "";
            std::string esc; esc.reserve(pat.size());
            for (char c : pat) { if (c == '\\' || c == '\"') esc.push_back('\\'); esc.push_back(c); }
            hh << "    inline const char* " << name << " = \"" << esc << "\";\n";
            };
        emit("GlobalVars", specs, results);
        emit("EntityList", specs, results);
        emit("ViewMatrix", specs, results);
        emit("ViewAngles", specs, results);
        emit("LocalPlayerController", specs, results);
        emit("LocalPlayerPawn", specs, results);
        emit("PlantedC4", specs, results);
        emit("InventoryServices", specs, results);
        hh << "}\n\n";
        hh << "} // namespace cs2\n";
        hh.close();
        g.print(Level::GOOD, "generated_offsets.hpp — OK");
    }

    {
        std::ostringstream fn; fn << "offsets_" << buildNumber << ".json";
        std::ofstream cj(fn.str(), std::ios::binary);
        cj << "{\n";
        cj << "  \"build\": " << buildNumber << ",\n";
        cj << "  \"client\": {\n";
        cj << "    \"dwEntityList\": \"" << hex32(rva_entity) << "\",\n";
        cj << "    \"dwViewMatrix\": \"" << hex32(rva_matrix) << "\",\n";
        cj << "    \"dwViewAngles\": \"" << hex32(rva_angles) << "\",\n";
        cj << "    \"dwLocalPlayerController\": \"" << hex32(rva_lpc) << "\",\n";
        cj << "    \"dwLocalPlayerPawn\": \"" << hex32(rva_lpp) << "\",\n";
        cj << "    \"dwGlobalVars\": \"" << hex32(rva_gvars) << "\",\n";
        cj << "    \"dwPlantedC4\": \"" << hex32(rva_c4) << "\"\n";
        cj << "  }\n";
        cj << "}\n";
        cj.close();
        g.print(Level::GOOD, "offsets_%u.json — OK", buildNumber);
    }

    g.section("Готово");
    g.print(Level::GOOD, "Файлы: dump_results.json, generated_offsets.hpp, offsets_%u.json", buildNumber);

    CloseHandle(h);
    return 0;
}
