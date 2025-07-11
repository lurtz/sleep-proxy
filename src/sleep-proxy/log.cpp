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
#include <utility>

namespace {
struct Syslog {
  const std::string identifier;
  Syslog(std::string ident, int option, int facility)
      : identifier(std::move(ident)) {
    openlog(identifier.c_str(), option, facility);
  }
  ~Syslog() { closelog(); }

  Syslog(Syslog const &) = delete;
  Syslog(Syslog &&) = delete;
  Syslog &operator=(Syslog const &) = delete;
  Syslog &operator=(Syslog &&) = delete;
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
std::unique_ptr<Syslog> logger{nullptr};
} // namespace

void setup_log(const std::string &ident, int option, int facility) {
  logger = nullptr;
  logger = std::make_unique<Syslog>(ident, option, facility);
}

void log_string(int priority, char const *const t) { log(priority, "%s", t); }

template <>
void log_string<std::string>(const int priority, std::string const &t) {
  log(priority, "%s", t.c_str());
}

void log(const int priority, const char *format, ...) {
  static std::mutex log_mutex;
  std::lock_guard<std::mutex> const lg(log_mutex);
  va_list args;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
  va_start(args, format);
  if (logger == nullptr) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    std::vprintf(format, args);
    // intention is to use the same library to add \n which was also used to
    // print the log message
    // NOLINTNEXTLINE(modernize-use-std-print)
    std::printf("\n");
  } else {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    vsyslog(priority, format, args);
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
  va_end(args);
}
