#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace proc_util {
    bool GetPidByName(const wchar_t* name, DWORD& pid);
    std::string WstrToUtf8(const std::wstring& ws);
}

