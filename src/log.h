#pragma once

#include <syslog.h>
#include <string>
#include "to_string.h"

void setup_log(const std::string& ident, int option, int facility);

void log(const int priority, const char * format, ...);

template<typename T>
void log_string(const int priority, T&& t);

template<>
void log_string<std::string>(const int priority, std::string&& t);

template<typename T>
void log_string(const int priority, T&& t) {
        log_string(priority, to_string(std::forward<T>(t)));
}

