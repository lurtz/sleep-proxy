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

#include <string>
#include <vector>
#include <type_traits>
#include <algorithm>
#include <functional>

static const std::string iface_chars{"qwertzuiopasdfghjklyxcvbnm.-0123456789"};

std::string validate_iface(const std::string iface);

/**
 * check that mac is well formatted and return the mac with its hex chars
 * converted to uppercase. if mac containts ":" they are removed
 */
std::string validate_mac(std::string mac);

/**
 * strip any subnet or device information from ip
 * */
std::string get_pure_ip(const std::string& ip);

/**
 * returns the version of ip. possible values are AF_INET and AF_INET6
 */
int getAF(const std::string& ip);

template<typename Container, typename Func>
auto parse_items(Container&& items, Func&& parser) -> std::vector<typename std::result_of<decltype(parser)(const std::string&)>::type> {
        static_assert(std::is_same<typename std::decay<Container>::type::value_type, std::string>::value, "container has to carry std::string");
        std::vector<typename std::result_of<decltype(parser)(const std::string&)>::type> ret_val(items.size());
        std::transform(std::begin(items), std::end(items), std::begin(ret_val), std::forward<Func>(parser));
        return ret_val;
}

/**
 * checks the format of ip and appends standard subnet sizes if none are given
 */
std::string sanitize_ip(const std::string& ip);

