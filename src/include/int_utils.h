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

static int const base_10 = 10;
[[nodiscard]] int64_t stoll_with_checks(const std::string &s,
                                        int base = base_10);
[[nodiscard]] uint64_t stoull_with_checks(const std::string &s,
                                          int base = base_10);

/** range check for signed target types */
template <typename R, typename T>
[[nodiscard]] bool within_bounds(const T &val) noexcept
  requires std::is_signed<T>::value
{
  return std::numeric_limits<R>::lowest() <= val &&
         val <= std::numeric_limits<R>::max();
}

/** range check for unsigned target types */
template <typename R, typename T>
[[nodiscard]] bool within_bounds(const T &val) noexcept
  requires std::is_unsigned<T>::value
{
  return val <= std::numeric_limits<R>::max();
}

/** convert to signed types */
template <typename T>
[[nodiscard]] int64_t str_to_integral_helper(const std::string &string)
  requires std::is_signed<T>::value
{
  return stoll_with_checks(string);
}

/** convert to unsigned types */
template <typename T>
[[nodiscard]] uint64_t str_to_integral_helper(const std::string &string)
  requires std::is_unsigned<T>::value
{
  return stoull_with_checks(string);
}

/** converts string to any integral type */
template <typename T>
[[nodiscard]] T str_to_integral(const std::string &string) {
  auto value = str_to_integral_helper<T>(string);
  if (!within_bounds<T>(value)) {
    std::string mess = "value " + to_string(value) + " not in range " +
                       to_string(std::numeric_limits<T>::lowest()) + ".." +
                       to_string(std::numeric_limits<T>::max());
    throw std::out_of_range(mess);
  }
  return static_cast<T>(value);
}

[[nodiscard]] std::string uint32_t_to_eight_hex_chars(uint32_t i) noexcept;
