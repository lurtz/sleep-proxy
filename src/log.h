#pragma once

#include <syslog.h>
#include <string>
#include "to_string.h"

void setup_log(const std::string& ident, int option, int facility);

void log_string(const int priority, const std::string& message);

template<typename T>
void log_string(const int priority, T&& t) {
        log_string(priority, to_string(std::forward<T>(t)));
}

void log(const int priority, const char * format, ...);
