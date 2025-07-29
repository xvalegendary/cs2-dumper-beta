#pragma once
#include <windows.h>
#include <mutex>
#include <string>
#include <cstdarg>

namespace logx {

    enum class Level : uint8_t {
        TRACE, DEBUG, INFO, GOOD, WARN, ERR, SCAN, FOUND, SECTION
    };

    class Logger {
    public:
        Logger();
        void init();
        void print(Level lv, const char* fmt, ...);
        void section(const char* title);
        void banner();

    private:
        void vprint(Level lv, const char* fmt, va_list ap);

        HANDLE hOut_;
        bool vt_;
        WORD baseAttrs_;
        std::mutex mtx_;
    };

    extern Logger g;

} // namespace logx
