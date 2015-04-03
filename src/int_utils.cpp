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

#include "int_utils.h"
#include <cerrno>
#include <cstdlib>
#include "to_string.h"

namespace fallback {
namespace std {
const ::std::string numbers{"-0123456789abcdefABCDEF"};

long long int stoll(const ::std::string &s, const int base) {
  if (s.size() == 0 || !contains_only_valid_characters(s, numbers)) {
    throw ::std::invalid_argument("strtoll(): cannot convert string: " + s);
  }
  auto errno_save = errno;
  errno = 0;
  auto ret_val = strtoll(s.c_str(), nullptr, base);
  switch (errno) {
  case 0:
    break;
  case ERANGE:
    throw ::std::out_of_range("strtoll() failed to convert:" + s);
    break;
  default:
    throw ::std::invalid_argument("strtoll() failed to convert: " + s);
    break;
  }
  errno = errno_save;
  return ret_val;
}

unsigned long long int stoull(const ::std::string &s, const int base) {
  if (s.size() == 0 || !contains_only_valid_characters(s, numbers)) {
    throw ::std::invalid_argument("strtoull(): cannot convert string: " + s);
  }
  auto errno_save = errno;
  errno = 0;
  auto ret_val = strtoull(s.c_str(), nullptr, base);
  if (s.at(0) == '-') {
    errno = ERANGE;
  }
  switch (errno) {
  case 0:
    break;
  case ERANGE:
    throw ::std::out_of_range("strtoull() failed to convert:" + s);
    break;
  default:
    throw ::std::invalid_argument("strtoull() failed to convert: " + s);
    break;
  }
  errno = errno_save;
  return ret_val;
}
}
}

std::string one_byte_to_two_hex_chars(const uint8_t b) noexcept {
  char val[3] = {0};
  snprintf(val, sizeof(val), "%02x", b);
  return val;
}
