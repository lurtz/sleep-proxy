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

#pragma once

#include "to_string.h"
#include <string>
#include <syslog.h>

void setup_log(const std::string &ident, int option, int facility);

void log(int priority, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

void log_string(int priority, char const *t);

template <typename T> void log_string(int priority, T &&t);

template <> void log_string<std::string>(int priority, std::string &&t);

template <typename T> void log_string(const int priority, T &&t) {
  log_string(priority, to_string(std::forward<T>(t)));
}
