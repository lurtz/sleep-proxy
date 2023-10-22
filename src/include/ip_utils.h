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
#include <functional>
#include <string>
#include <type_traits>
#include <vector>

static const std::string iface_chars{"qwertzuiopasdfghjklyxcvbnm.-0123456789"};

std::string validate_iface(std::string const &iface);

template <typename Container, typename Func>
auto parse_items(Container &&items, Func &&parser) -> std::vector<
    typename std::invoke_result_t<decltype(parser), const std::string &>> {
  static_assert(std::is_same<typename std::decay<Container>::type::value_type,
                             std::string>::value,
                "container has to carry std::string");
  std::vector<
      typename std::invoke_result_t<decltype(parser), const std::string &>>
      ret_val(items.size());
  std::transform(std::begin(items), std::end(items), std::begin(ret_val),
                 std::forward<Func>(parser));
  return ret_val;
}
