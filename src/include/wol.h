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

#include <cstdint>
#include <netinet/ether.h>
#include <string>
#include <vector>

enum class Wol_method : std::uint8_t { ethernet, udp };

/**
 * create the payload for a UDP wol packet to be broadcast in to the network
 */
[[nodiscard]] std::vector<uint8_t> create_wol_payload(const ether_addr &mac);

/**
 * validates and converts human readable wol method into its respective enum
 * value
 */
[[nodiscard]] Wol_method parse_wol_method(const std::string &wol_method);

std::ostream &operator<<(std::ostream &out, const Wol_method &wol_method);

/**
 * Send a WOL UDP packet to the given mac
 */
void wol_udp(const ether_addr &mac);

void wol_ethernet(const std::string &iface, const ether_addr &mac);
