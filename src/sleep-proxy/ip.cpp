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

#include "ip.h"
#include "to_string.h"
#include <arpa/inet.h>

uint8_t const ip::ipv4_header_size;
uint8_t const ip::ipv6_header_size;
uint8_t const ip::ipv6_address_size_byte;

inline std::ostream &operator<<(std::ostream &out, const ip::Version &v) {
  switch (v) {
  case ip::Version::ipv4:
    // NOLINTNEXTLINE
    out << 4;
    break;
  case ip::Version::ipv6:
    // NOLINTNEXTLINE
    out << 6;
    break;
  default:
    out << "unknown";
    break;
  }
  return out;
}

std::ostream &operator<<(std::ostream &out, const ip &ip) {
  out << "IPv" << ip.version() << ": ";
  out << "dst = " << ip.destination().pure()
      << ", src = " << ip.source().pure();
  return out;
}

ip::ip(ip::Version const version, size_t const header_length,
       IP_address const source, IP_address const destination,
       uint8_t const payload_protocol)
    : m_version(version), m_header_length(header_length), m_source(source),
      m_destination(destination), m_payload_protocol(payload_protocol) {}

ip::Version ip::version() const { return m_version; }

size_t ip::header_length() const { return m_header_length; }

IP_address ip::source() const { return m_source; }

IP_address ip::destination() const { return m_destination; }

uint8_t ip::payload_protocol() const { return m_payload_protocol; }

IP_address get_ipv6_address(const in6_addr &addr) {
  static auto const all_bits_specified = uint8_t{128};
  IP_address ipa{};
  ipa.family = AF_INET6;
  ipa.address.ipv6 = addr;
  ipa.subnet = all_bits_specified;
  return ipa;
}
