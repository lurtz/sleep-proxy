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

#include "ethernet.h"
#include "ip.h"
#include <memory>
#include <pcap/pcap.h>
#include <tuple>
#include <vector>

/**
 * Ethernet, IP and TCP/UDP header in one tuple
 * */
using basic_headers =
    std::tuple<std::unique_ptr<Link_layer>, std::unique_ptr<ip>>;

/**
 * Prints the headers to stdout
 * */
std::ostream &operator<<(std::ostream &out, const basic_headers &headers);

/**
 * Extracts the Ethernet, IP and TCP/UDP headers from packet
 * */
[[nodiscard]] basic_headers get_headers(int type,
                                        const std::vector<u_char> &packet);

/**
 * Saves the lower 3 layers and all the data which has been intercepted
 * using pcap.
 */
struct Catch_incoming_connection {
  const int link_layer_type;
  basic_headers headers;
  std::vector<uint8_t> data;

  explicit Catch_incoming_connection(int link_layer_typee);

  void operator()(const pcap_pkthdr *header, const u_char *packet);
};
