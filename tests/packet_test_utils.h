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

#include <memory>
#include <vector>
#include <ip.h>
#include <ethernet.h>
#include <ip_address.h>
#include <file_descriptor.h>
#include <tuple>
#include <to_string.h>
#include <spawn_process.h>

std::vector<uint8_t> to_binary(const std::string &hex);

void test_ll(const std::unique_ptr<Link_layer> &ll, const size_t length,
             const std::string &src, const ip::Version payload_protocol,
             const std::string &info);

void test_ip(const std::unique_ptr<ip> &ip, const ip::Version v,
             const std::string &src, const std::string &dst,
             const size_t header_length, const ip::Payload pl_type);

bool operator==(const Link_layer &lhs, const Link_layer &rhs);

bool operator==(const ip &lhs, const ip &rhs);

bool operator<(IP_address const &lhs, IP_address const &rhs);

std::vector<std::string> get_ip_neigh_output();

typedef std::vector<std::tuple<std::string, IP_address>> Iface_Ips;

Iface_Ips get_iface_ips(std::vector<std::string> const ip_neigh_content);

template <typename Container0, typename Container1>
std::vector<std::tuple<typename Container0::value_type,
                       typename Container1::value_type>>
cartesian_product(Container0 const &c0, Container1 const &c1) {
  std::vector<std::tuple<typename Container0::value_type,
                         typename Container1::value_type>> retVal;
  for (auto const &c0item : c0) {
    for (auto const &c1item : c1) {
      retVal.emplace_back(std::make_tuple(c0item, c1item));
    }
  }
  return retVal;
}
