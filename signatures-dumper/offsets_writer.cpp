#include "offsets_writer.hpp"
#include <fstream>
#include <iomanip>
#include <ctime>

namespace offsets_writer {

    void WriteJson(const std::string& filename, uint32_t pid, uint32_t buildNumber, const std::vector<Found>& results) {
        std::ofstream js(filename, std::ios::binary);
        js << "{\n";
        js << "  \"pid\": " << pid << ",\n";
        js << "  \"buildNumber\": " << buildNumber << ",\n";
        js << "  \"results\": [\n";
        for (size_t i = 0; i < results.size(); ++i) {
            const auto& e = results[i];
            js << "    {\n";
            js << "      \"name\": \"" << e.name << "\",\n";
            js << "      \"module\": \"" << e.module << "\",\n";
            js << "      \"pattern\": \"" << e.pattern << "\",\n";
            js << "      \"ok\": " << (e.ok ? "true" : "false") << "\n";
            js << "    }" << (i + 1 == results.size() ? "\n" : ",\n");
        }
        js << "  ]\n";
        js << "}\n";
        js.close();
    }

    void WriteHpp(const std::string& filename, uint32_t buildNumber, const std::vector<Found>& results) {
        std::time_t t = std::time(nullptr); std::tm tm{}; gmtime_s(&tm, &t);
        char timebuf[64]; std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S UTC", &tm);

        std::ofstream hh(filename, std::ios::binary);
        hh << "#pragma once\n\n";
        hh << "// CS2 Dumper (beta)\n";
        hh << "// Generated at " << timebuf << "\n\n";
        // ... генерируй нужные константы как раньше
        hh.close();
    }

}
