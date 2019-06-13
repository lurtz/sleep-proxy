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

#include <algorithm>
#include <iterator>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

/**
 * Writes the items of a vector seperated by ", " into out
 */
template <typename T, typename Alloc>
std::ostream &operator<<(std::ostream &out, std::vector<T, Alloc> v) {
  std::ostream_iterator<T> iter(out, ", ");
  if (std::begin(v) != std::end(v)) {
    std::copy(std::begin(v), std::end(v) - 1, iter);
    out << static_cast<T>(*(std::end(v) - 1));
  }
  return out;
}

template <typename T> std::string to_string(T &&t) {
  std::stringstream ss;
  ss << t;
  return ss.str();
}

bool contains_only_valid_characters(const std::string &input,
                                    const std::string &valid_chars);

std::string test_characters(const std::string &input,
                            const std::string &valid_chars,
                            std::string error_message);

template <typename Container>
std::vector<const char *> get_c_string_array(const Container &strings) {
  static_assert(std::is_same<typename std::decay<Container>::type::value_type,
                             std::string>::value,
                "container has to carry std::string");
  std::vector<const char *> ch_ptr;
  std::transform(std::begin(strings), std::end(strings),
                 std::back_inserter(ch_ptr),
                 [](const std::string &s) { return s.c_str(); });
  // null termination
  ch_ptr.push_back(nullptr);
  return ch_ptr;
}
