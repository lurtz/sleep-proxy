#include "log.h"
#include <cstdarg>
#include <memory>
#include <mutex>

struct Syslog {
        const std::string identifier;
        Syslog(const std::string ident, int option, int facility) : identifier(std::move(ident)) {
                openlog(identifier.c_str(), option, facility);
        }
        ~Syslog() {
                closelog();
        }
};

std::unique_ptr<Syslog> logger{nullptr};

void setup_log(const std::string& ident, int option, int facility) {
        logger = std::unique_ptr<Syslog>(new Syslog(ident, option, facility));
}

void log_string(const int priority, const std::string& message) {
        log(priority, "%s", message.c_str());
}

void log(const int priority, const char * format, ...) {
        static std::mutex log_mutex;
        std::lock_guard<std::mutex> lg(log_mutex);
        va_list args;
        va_start(args, format);
        if (logger == nullptr) {
                std::vprintf(format, args);
        } else {
                vsyslog(priority, format, args);
        }
        va_end(args);
}
