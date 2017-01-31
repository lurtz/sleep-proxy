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

#include <arpa/inet.h>
#include <ostream>
#include <string>

struct IP_address {
  int family;
  union {
    in_addr ipv4;
    in6_addr ipv6;
  } address;
  uint8_t subnet;

  std::string pure() const;

  std::string with_subnet() const;

  bool operator==(const IP_address &rhs) const;
};

IP_address parse_ip(const std::string &ip);

std::string get_pure_ip(const IP_address &ip);

std::ostream &operator<<(std::ostream &out, const IP_address &ipa);
