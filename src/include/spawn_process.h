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

#include "file_descriptor.h"
#include "to_string.h"
#include <cstdint>
#include <string>
#include <type_traits>

[[nodiscard]] uint8_t wait_until_pid_exits(const pid_t &pid);

[[nodiscard]] uint8_t spawn_wrapper(std::vector<char *> params,
                                    File_descriptor const &in,
                                    File_descriptor const &out);

template <typename Container>
uint8_t spawn(Container const &cmd,
              File_descriptor const &in = File_descriptor(),
              File_descriptor const &out = File_descriptor()) {
  static_assert(std::is_same_v<typename std::decay<Container>::type::value_type,
                               std::string>,
                "container has to carry std::string");

  // get char * of each string
  auto cmd_vectors = to_vector_strings(cmd);
  auto ch_ptr2 = get_c_string_array(cmd_vectors);

  return spawn_wrapper(ch_ptr2, in, out);
}
