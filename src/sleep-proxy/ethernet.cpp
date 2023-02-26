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

#include "ethernet.h"
#include "int_utils.h"
#include <iterator>
#include <stdexcept>

uint8_t const Link_layer::lcc_header_size;
uint8_t const Link_layer::lcc_address_size;
uint8_t const Link_layer::ethernet_header_size;
uint16_t const Link_layer::ETHERTYPE_WAKE_ON_LAN;

std::ostream &operator<<(std::ostream &out, const Link_layer &ll) {
  out << ll.get_info();
  return out;
}

Link_layer::Link_layer(size_t const header_length, ether_addr const source,
                       uint16_t const payload_protocol, std::string info)
    : m_header_length(header_length), m_source(source),
      m_payload_protocol(payload_protocol), m_info(std::move(info)) {}

size_t Link_layer::header_length() const { return m_header_length; }

uint16_t Link_layer::payload_protocol() const { return m_payload_protocol; }

std::string Link_layer::get_info() const { return m_info; }

ether_addr Link_layer::source() const { return m_source; }

std::vector<uint8_t> to_vector(const ether_addr &mac) {
  return {std::begin(mac.ether_addr_octet), std::end(mac.ether_addr_octet)};
}

std::vector<uint8_t> create_ethernet_header(const ether_addr &dmac,
                                            const ether_addr &smac,
                                            const uint16_t type) {
  auto binary = to_vector(dmac) + to_vector(smac);
  static auto const shift_byte = uint8_t{8};
  binary.push_back(static_cast<uint8_t>(type >> shift_byte));
  static auto const and_byte = uint8_t{0xFF};
  binary.push_back(static_cast<uint8_t>(type & and_byte));
  return binary;
}

ether_addr mac_to_binary(const std::string &mac) {
  ether_addr addr{{0}};
  if (ether_aton_r(mac.c_str(), &addr) == nullptr) {
    throw std::runtime_error("invalid mac: " + mac);
  }
  return addr;
}

std::string binary_to_mac(const ether_addr &mac) {
  static auto const characters = uint8_t{12};
  static auto const double_colons = uint8_t{5};
  static auto const nul_termination = uint8_t{1};
  static auto const array_size = characters + double_colons + nul_termination;
  auto canon_mac = std::array<char, array_size>{};
  ether_ntoa_r(&mac, canon_mac.data());
  return canon_mac.data();
}
