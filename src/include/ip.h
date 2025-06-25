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
#include "ip_address.h"
#include "log.h"
#include <arpa/inet.h>
#include <cstdint>
#include <iterator>
#include <memory>
#include <net/ethernet.h>
#include <netinet/in.h>

struct ip {
  constexpr static auto ipv4_header_size = uint8_t{20};
  constexpr static auto ipv6_header_size = uint8_t{40};
  constexpr static auto ipv4_address_size_byte = uint8_t{4};
  constexpr static auto ipv6_address_size_byte = uint8_t{16};

  enum Version { ipv4 = ETHERTYPE_IP, ipv6 = ETHERTYPE_IPV6 };
  enum Payload { TCP = IPPROTO_TCP, UDP = IPPROTO_UDP };

  ip::Version m_version;
  size_t m_header_length;
  IP_address m_source;
  IP_address m_destination;
  uint8_t m_payload_protocol;

  ip(ip::Version version, size_t header_length, IP_address source,
     IP_address destination, uint8_t payload_protocol);

  /** which IP version */
  [[nodiscard]] Version version() const;

  /** length of IP header in bytes */
  [[nodiscard]] size_t header_length() const;

  /** source address */
  [[nodiscard]] IP_address source() const;

  /** destination address */
  [[nodiscard]] IP_address destination() const;

  /** which protocol header to expect next */
  [[nodiscard]] uint8_t payload_protocol() const;
};

/** writes ip into out which every information available to the base class */
std::ostream &operator<<(std::ostream &out, const ip &ip);

template <typename iterator>
[[nodiscard]] bool
ethernet_payload_and_ip_version_dont_match(uint16_t const type, iterator data) {
  static_assert(std::is_same<typename iterator::value_type, uint8_t>::value,
                "container has to carry u_char or uint8_t");

  auto const version = static_cast<uint8_t>(*data >> 4);
  bool const result = (type == ip::Version::ipv4 && version != 4) ||
                      (type == ip::Version::ipv6 && version != 6);
  if (result) {
    log_string(LOG_ERR, "ethernet type and ip version do not match");
  }
  return result;
}

[[nodiscard]] IP_address get_ipv6_address(const in6_addr &addr);

template <typename iterator>
[[nodiscard]] std::unique_ptr<ip> parse_ipv4(iterator data, iterator end) {
  check_type_and_range(data, end, ip::ipv4_header_size);
  uint8_t const ip_vhl = *data;
  size_t const header_length = static_cast<uint8_t>((ip_vhl & 0x0f) * 4);
  // NOLINTNEXTLINE
  std::advance(data, 9);
  uint8_t const ip_p = *data;
  std::advance(data, 3);
  struct in_addr ip_src{};
  std::copy(data, data + ip::ipv4_address_size_byte,
            reinterpret_cast<uint8_t *>(&ip_src));
  std::advance(data, ip::ipv4_address_size_byte);
  struct in_addr ip_dst{};
  std::copy(data, data + ip::ipv4_address_size_byte,
            reinterpret_cast<uint8_t *>(&ip_dst));
  static auto const no_subnet = uint8_t{32};
  return std::make_unique<ip>(ip::ipv4, header_length,
                              IP_address{AF_INET, {ip_src}, no_subnet},
                              IP_address{AF_INET, {ip_dst}, no_subnet}, ip_p);
}

template <typename iterator>
[[nodiscard]] std::unique_ptr<ip> parse_ipv6(iterator data, iterator end) {
  check_type_and_range(data, end, ip::ipv6_header_size);
  // NOLINTNEXTLINE
  std::advance(data, 6);
  uint8_t const next_header = *data;
  std::advance(data, 2);
  in6_addr source_address{};
  // NOLINTNEXTLINE
  std::copy(data, data + ip::ipv6_address_size_byte, source_address.s6_addr);
  std::advance(data, ip::ipv6_address_size_byte);
  in6_addr dest_address{};
  // NOLINTNEXTLINE
  std::copy(data, data + ip::ipv6_address_size_byte, dest_address.s6_addr);
  return std::make_unique<ip>(ip::ipv6, ip::ipv6_header_size,
                              get_ipv6_address(source_address),
                              get_ipv6_address(dest_address), next_header);
}

template <typename iterator>
[[nodiscard]] std::unique_ptr<ip> parse_ip(uint16_t const type, iterator data,
                                           iterator end) {
  // check wether type and the version the ip headers matches
  if (ethernet_payload_and_ip_version_dont_match(type, data)) {
    return nullptr;
  }
  // construct the IPv4/IPv6 header
  switch (type) {
  case ip::Version::ipv4:
    return parse_ipv4(data, end);
  case ip::Version::ipv6:
    return parse_ipv6(data, end);
  // do not know the IP version which is given
  default:
    return nullptr;
  }
}
