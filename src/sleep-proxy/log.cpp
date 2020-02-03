// Copyright (C) 2014  Lutz Reinhardt
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#include "log.h"
#include <cstdarg>
#include <memory>
#include <mutex>

namespace {
struct Syslog {
  const std::string identifier;
  Syslog(const std::string ident, int option, int facility)
      : identifier(std::move(ident)) {
    openlog(identifier.c_str(), option, facility);
  }
  ~Syslog() { closelog(); }
};

std::unique_ptr<Syslog> logger{nullptr};
} // namespace

void setup_log(const std::string &ident, int option, int facility) {
  logger = nullptr;
  logger = std::unique_ptr<Syslog>(new Syslog(ident, option, facility));
}

template <> void log_string<std::string>(const int priority, std::string &&t) {
  log(priority, "%s", t.c_str());
}

void log(const int priority, const char *format, ...) {
  static std::mutex log_mutex;
  std::lock_guard<std::mutex> const lg(log_mutex);
  va_list args;
  va_start(args, format);
  if (logger == nullptr) {
    std::vprintf(format, args);
    std::printf("\n");
  } else {
    vsyslog(priority, format, args);
  }
  va_end(args);
}
