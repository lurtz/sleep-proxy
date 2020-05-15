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

#include "to_string.h"
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <vector>

std::string to_string(char const *const t) { return t; }

bool contains_only_valid_characters(const std::string &input,
                                    const std::string &valid_chars) {
  const bool b = std::all_of(std::begin(input), std::end(input), [&](char ch) {
    return valid_chars.find(ch) != std::string::npos;
  });
  return b;
}

std::string test_characters(const std::string &input,
                            const std::string &valid_chars,
                            const std::string &error_message) {
  if (!contains_only_valid_characters(input, valid_chars)) {
    throw std::runtime_error(error_message);
  }
  return input;
}
