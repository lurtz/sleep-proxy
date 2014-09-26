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

#include <sstream>
#include <string>
#include <algorithm>
#include <iterator>

template<typename Container, typename Func>
std::string join(Container c, Func fun, std::string sep) {
        typedef typename std::result_of<decltype(fun)(typename Container::value_type)>::type input_type;
        std::stringstream ss;
        std::ostream_iterator<input_type> iter(ss, sep.c_str());
        if (std::begin(c) != std::end(c)) {
                std::transform(std::begin(c), std::end(c)-1, iter, fun);
                ss << fun(*(std::end(c)-1));
        }
        return ss.str();
}

template<typename T>
T repeat(const T& s, const unsigned int count, T&& init = T()) {
        std::vector<T> range(count, s);
        return std::accumulate(std::begin(range), std::end(range), init);
}

template<typename T, typename Alloc>
std::vector<T, Alloc> operator+(std::vector<T, Alloc>&& lhs, const std::vector<T, Alloc>& rhs) {
        lhs.insert(std::end(lhs), std::begin(rhs), std::end(rhs));
        return std::move(lhs);
}

