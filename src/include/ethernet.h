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

#include "container_utils.h"
#include "to_string.h"
#include <arpa/inet.h>
#include <array>
#include <cstdint>
#include <memory>
#include <netinet/ether.h>
#include <ostream>
#include <pcap/bpf.h>
#include <sys/types.h> // needed by bpf.h after openwrt 15.05+
#include <vector>

struct Link_layer {
  static auto const lcc_header_size = uint8_t{16};
  static auto const lcc_address_size = uint8_t{8};
  static auto const ethernet_header_size = uint8_t{14};
  static auto const ETHERTYPE_WAKE_ON_LAN = uint16_t{0x0842};

  size_t m_header_length;
  ether_addr m_source;
  uint16_t m_payload_protocol;
  std::string m_info;

  Link_layer(size_t header_length, ether_addr source, uint16_t payload_protocol,
             std::string info);

  size_t header_length() const;

  uint16_t payload_protocol() const;

  std::string get_info() const;

  ether_addr source() const;
};

std::ostream &operator<<(std::ostream &out, const Link_layer &ll);

std::vector<uint8_t> create_ethernet_header(const ether_addr &dmac,
                                            const ether_addr &smac,
                                            uint16_t type);

std::vector<uint8_t> to_vector(const ether_addr &mac);

ether_addr mac_to_binary(const std::string &mac);

std::string binary_to_mac(const ether_addr &mac);

template <typename iterator>
std::unique_ptr<Link_layer> parse_linux_cooked_capture(iterator data,
                                                       iterator end) {
  // see https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
  check_type_and_range(data, end, Link_layer::lcc_header_size);
  std::advance(data, 2);
  uint16_t const device_type =
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      ntohs(*reinterpret_cast<uint16_t const *>(&(*data)));
  if (device_type != ARPHRD_ETHER && device_type != ARPHRD_LOOPBACK) {
    throw std::runtime_error(
        "Linux_cooked_capture only supports ethernet or loopback, got: " +
        to_string(device_type) + " (look in net/if_arp.h for value)");
  }
  std::advance(data, 2);
  uint16_t const ll_address_length =
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      ntohs(*reinterpret_cast<uint16_t const *>(&(*data)));
  if (ll_address_length != ETHER_ADDR_LEN) {
    throw std::length_error("invalid link address size");
  }
  std::advance(data, 2);
  ether_addr ether_shost{};
  std::copy(data, data + ETHER_ADDR_LEN,
            std::begin(ether_shost.ether_addr_octet));
  std::advance(data, Link_layer::lcc_address_size);
  uint16_t const payload_type =
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      ntohs(*reinterpret_cast<uint16_t const *>(&(*data)));
  std::string const info =
      "Linux cooked capture: src: " + binary_to_mac(ether_shost);
  return std::make_unique<Link_layer>(Link_layer::lcc_header_size, ether_shost,
                                      payload_type, info);
}

template <typename iterator>
std::unique_ptr<Link_layer> parse_ethernet(iterator data, iterator end) {
  size_t const header_size = 14;
  check_type_and_range(data, end, header_size);
  ether_addr ether_dhost{};
  std::copy(data, data + ETHER_ADDR_LEN,
            std::begin(ether_dhost.ether_addr_octet));
  std::advance(data, ETHER_ADDR_LEN);
  ether_addr ether_shost{};
  std::copy(data, data + ETHER_ADDR_LEN,
            std::begin(ether_shost.ether_addr_octet));
  std::advance(data, ETHER_ADDR_LEN);
  uint16_t const ether_type =
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      ntohs(*reinterpret_cast<uint16_t const *>(&(*data)));
  std::string const info = "Ethernet: dst = " + binary_to_mac(ether_dhost) +
                           ", src = " + binary_to_mac(ether_shost);
  return std::make_unique<Link_layer>(header_size, ether_shost, ether_type,
                                      info);
}

template <typename iterator>
std::unique_ptr<Link_layer> parse_VLAN_Header(iterator data, iterator end) {
  size_t const header_size = 4;
  check_type_and_range(data, end, header_size);
  std::advance(data, 2);
  uint16_t const payload_type =
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      ntohs(*reinterpret_cast<uint16_t const *>(&(*data)));
  ether_addr const ether_shost{{0}};
  return std::make_unique<Link_layer>(header_size, ether_shost, payload_type,
                                      "VLAN Header");
}

template <typename iterator>
std::unique_ptr<Link_layer> parse_link_layer(const int type, iterator data,
                                             iterator end) {
  switch (type) {
  case DLT_LINUX_SLL:
    return parse_linux_cooked_capture(data, end);
  case DLT_EN10MB:
    return parse_ethernet(data, end);
  case ETHERTYPE_VLAN:
    return parse_VLAN_Header(data, end);
  default:
    return nullptr;
  }
}
