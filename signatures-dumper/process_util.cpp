#include "process_util.hpp"
#include <tlhelp32.h>
#include <windows.h>

namespace proc_util {

    bool GetPidByName(const wchar_t* name, DWORD& pid) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return false;
        PROCESSENTRY32W pe{ sizeof(pe) }; bool ok = false;
        if (Process32FirstW(hSnap, &pe)) {
            do { if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; ok = true; break; } } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap); return ok;
    }

    std::string WstrToUtf8(const std::wstring& ws) {
        if (ws.empty()) return {};
        int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
        std::string out(len, 0);
        WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), out.data(), len, nullptr, nullptr); return out;
    }

}
