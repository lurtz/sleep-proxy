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
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

template <typename T> T identity(const T &t) { return t; }

template <typename Container, typename Func>
std::string join(Container c, Func fun, const std::string &sep) {
  using input_type = typename std::result_of<decltype(fun)(
      typename Container::value_type)>::type;
  std::stringstream ss;
  std::ostream_iterator<input_type> iter(ss, sep.c_str());
  if (std::begin(c) != std::end(c)) {
    std::transform(std::begin(c), std::end(c) - 1, iter, fun);
    ss << fun(*(std::end(c) - 1));
  }
  return ss.str();
}

template <typename T, typename Alloc>
std::vector<T, Alloc> operator+(std::vector<T, Alloc> &&lhs,
                                const std::vector<T, Alloc> &rhs) {
  lhs.insert(std::end(lhs), std::begin(rhs), std::end(rhs));
  return std::move(lhs);
}

template <typename iterator>
void check_type_and_range(iterator data, iterator end, size_t const min_size) {
  static_assert(std::is_same<typename iterator::value_type, uint8_t>::value,
                "container has to carry u_char or uint8_t");
  if (data >= end || static_cast<size_t>(std::distance(data, end)) < min_size) {
    throw std::length_error("not enough data");
  }
}

template <typename Container>
std::vector<Container> split(Container const &c,
                             typename Container::value_type const &delimiter) {
  typename Container::const_iterator iter{std::begin(c)};
  std::vector<Container> results;
  while (iter != std::end(c)) {
    typename Container::const_iterator const possible_delim =
        std::find(iter, std::end(c), delimiter);
    results.emplace_back(iter, possible_delim);
    iter = possible_delim;
    if (iter != std::end(c)) {
      iter++;
    }
  }
  return results;
}
