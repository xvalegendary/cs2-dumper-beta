#include "pattern_util.hpp"
#include <windows.h>
#include <sstream>
#include <stdexcept>

namespace pattern_util {

    Pattern ParseIda(const std::string& ida) {
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
    size_t FindPatternBMH(const uint8_t* data, size_t size, const Pattern& p) {
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
    bool ReadU64(HANDLE h, uint64_t addr, uint64_t& out) {
        SIZE_T br = 0; return ReadProcessMemory(h, (LPCVOID)addr, &out, sizeof(out), &br) && br == sizeof(out);
    }
    bool ReadI32(HANDLE h, uint64_t addr, int32_t& out) {
        SIZE_T br = 0; return ReadProcessMemory(h, (LPCVOID)addr, &out, sizeof(out), &br) && br == sizeof(out);
    }
    uint64_t RipTarget(uint64_t instrAbs, int32_t disp, int instrLen) {
        return instrAbs + instrLen + (int64_t)disp;
    }

} // namespace pattern_util
