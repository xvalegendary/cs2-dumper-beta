#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <windows.h>

struct ModuleInfoEx {
    HMODULE  hMod{};
    uint64_t base{};
    uint32_t size{};
    std::string name;
    std::string path;
};

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

struct Pattern {
    std::vector<uint8_t> b;
    std::vector<uint8_t> m;
};

enum class Resolve { NONE, RIP_ADDR, RIP_DEREF };

struct SigSpec {
    std::string name;
    std::vector<std::string> modules;
    std::vector<std::string> patterns;
    Resolve how{ Resolve::NONE };
    int dispOff{ 3 };
    int instrLen{ 7 };
    bool post_viewAngles_fix{ false };
};

struct Found {
    std::string name;
    std::string module;
    std::string pattern;
    uint64_t base{};
    uint64_t size{};
    uint64_t instr{};
    uint64_t addr{};
    uint64_t qword{};
    uint32_t rva_instr{};
    uint32_t rva_addr{};
    bool ok{};
    int score{};
    std::string notes;
};

struct Known {
    const char* name;
    uint32_t rva;
};
