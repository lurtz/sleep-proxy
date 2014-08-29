#pragma once

#include <syslog.h>
#include <string>

void setup_log(const std::string& ident, int option, int facility);
void log(const int priority, const std::string& message);
void log(const int priority, const char * format, ...);
