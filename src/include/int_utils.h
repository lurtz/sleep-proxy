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
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>

static auto const base_10 = int{10};
int64_t stoll_with_checks(const std::string &s, int base = base_10);
uint64_t stoull_with_checks(const std::string &s, int base = base_10);

/** range check for signed target types */
template <typename R, typename T,
          typename std::enable_if<std::is_signed<T>::value>::type * = nullptr>
bool within_bounds(const T &val) noexcept {
  return std::numeric_limits<R>::lowest() <= val &&
         val <= std::numeric_limits<R>::max();
}

/** range check for unsigned target types */
template <typename R, typename T,
          typename std::enable_if<std::is_unsigned<T>::value>::type * = nullptr>
bool within_bounds(const T &val) noexcept {
  return val <= std::numeric_limits<R>::max();
}

/** convert to signed types */
template <typename T,
          typename std::enable_if<std::is_signed<T>::value>::type * = nullptr>
int64_t str_to_integral_helper(const std::string &string) {
  return stoll_with_checks(string);
}

/** convert to unsigned types */
template <typename T,
          typename std::enable_if<std::is_unsigned<T>::value>::type * = nullptr>
uint64_t str_to_integral_helper(const std::string &string) {
  return stoull_with_checks(string);
}

/** converts string to any integral type */
template <typename T> T str_to_integral(const std::string &string) {
  auto value = str_to_integral_helper<T>(string);
  if (!within_bounds<T>(value)) {
    std::string mess = "value " + to_string(value) + " not in range " +
                       to_string(std::numeric_limits<T>::lowest()) + ".." +
                       to_string(std::numeric_limits<T>::max());
    throw std::out_of_range(mess);
  }
  return static_cast<T>(value);
}

std::string uint32_t_to_eight_hex_chars(uint32_t i) noexcept;
