#include "logx.hpp"
#include <cstdio>
#include <sstream>
#include <windows.h>

namespace logx {

    Logger g;

    Logger::Logger() : hOut_(GetStdHandle(STD_OUTPUT_HANDLE)), vt_(false), baseAttrs_(0) {}

    static std::string rgb(int r, int g, int b) {
        char buf[32];
        snprintf(buf, sizeof(buf), "\x1b[38;2;%d;%d;%dm", r, g, b);
        return buf;
    }
    static std::string now_time() {
        SYSTEMTIME st; GetLocalTime(&st);
        char buf[32];
        snprintf(buf, sizeof(buf), "%02u:%02u:%02u", st.wHour, st.wMinute, st.wSecond);
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

    void Logger::init() {
        CONSOLE_SCREEN_BUFFER_INFO ci{};
        if (GetConsoleScreenBufferInfo(hOut_, &ci)) baseAttrs_ = ci.wAttributes;
        DWORD mode = 0;
        if (GetConsoleMode(hOut_, &mode)) {
            DWORD want = mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT;
            vt_ = SetConsoleMode(hOut_, want);
        }
    }

    void Logger::vprint(Level lv, const char* fmt, va_list ap) {
        char msg[4096];
        vsnprintf(msg, sizeof(msg), fmt, ap);

        std::lock_guard<std::mutex> lk(mtx_);
        std::string t = now_time();
        const char* ic = icon(lv);

        if (vt_) {
            std::string line;
            std::string color = rgb(120, 120, 120);
            line += color + "[" + t + "] " + "\x1b[0m";
            line += rgb(96, 181, 255) + ic + " " + "\x1b[0m ";
            line += msg;
            line += "\n";
            DWORD bw; WriteConsoleA(hOut_, line.c_str(), (DWORD)line.size(), &bw, nullptr);
        }
        else {
            DWORD bw;
            std::ostringstream oss;
            oss << "[" << t << "] " << ic << " ";
            auto s = oss.str();
            SetConsoleTextAttribute(hOut_, baseAttrs_);
            WriteConsoleA(hOut_, s.c_str(), (DWORD)s.size(), &bw, nullptr);
            WriteConsoleA(hOut_, msg, (DWORD)strlen(msg), &bw, nullptr);
            WriteConsoleA(hOut_, "\n", 1, &bw, nullptr);
            SetConsoleTextAttribute(hOut_, baseAttrs_);
        }
    }
    void Logger::print(Level lv, const char* fmt, ...) {
        va_list ap; va_start(ap, fmt); vprint(lv, fmt, ap); va_end(ap);
    }
    void Logger::section(const char* title) {
        print(Level::SECTION, "%s", title);
    }
    void Logger::banner() {
        print(Level::GOOD, "==================== CS2 Dumper ====================");
    }
} // namespace logx
