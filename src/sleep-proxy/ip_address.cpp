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

#include "ip_address.h"
#include "container_utils.h"
#include "int_utils.h"
#include "log.h"
#include "to_string.h"
#include <array>

namespace {
int get_af(const std::string &ip) {
  in6_addr ipv6;
  if (inet_pton(AF_INET, ip.c_str(), &ipv6) == 1) {
    return AF_INET;
  }
  if (inet_pton(AF_INET6, ip.c_str(), &ipv6) == 1) {
    return AF_INET6;
  }
  throw std::runtime_error("ip " + ip +
                           " is not as IPv4 or IPv6 recognizeable");
}

uint8_t get_subnet(const int version,
                   const std::vector<std::string> &ip_subnet) {
  uint8_t subnet;
  // if no subnet size is given, append standard values
  if (ip_subnet.size() == 1) {
    subnet = 24;
    if (version == AF_INET6) {
      subnet = ip_subnet.at(0) != "::1" ? 64 : 128;
    }
  } else {
    subnet = str_to_integral<uint8_t>(ip_subnet.at(1));
  }
  // check if the subnet size is in correct bounds
  const uint8_t maxsubnetlen = version == AF_INET ? 32 : 128;
  if (subnet > maxsubnetlen) {
    std::string ss = "Subnet " + to_string(subnet) + " is not in range 0.." +
                     to_string(maxsubnetlen);
    throw std::invalid_argument(ss);
  }
  return subnet;
}
} // namespace

std::string IP_address::pure() const {
  std::array<char, INET6_ADDRSTRLEN> text{{0}};
  inet_ntop(family, &address.ipv6, text.data(),
            static_cast<socklen_t>(text.size()));
  return text.data();
}

std::string IP_address::with_subnet() const {
  return pure() + "/" + to_string(static_cast<int>(subnet));
}

bool IP_address::operator==(const IP_address &rhs) const {
  bool equal = family == rhs.family;
  equal &= subnet == rhs.subnet;
  equal &= pure() == rhs.pure();
  return equal;
}

static const std::string ip_chars{
    "0123456789.abcdefghijklmnopqrstuvwxyzABCDEF:/%"};

IP_address parse_ip(const std::string &ip) {
  if (ip.empty()) {
    throw std::invalid_argument("given ip is empty");
  }
  log_string(LOG_INFO, "parsing ip: " + ip);
  test_characters(ip, ip_chars, "ip contains invalid characters: " + ip);
  // one slash or no slash
  if (ip.find('/') != ip.rfind('/')) {
    throw std::invalid_argument("Too many / in IP");
  }
  // getAF() throws if inet_pton() can not understand the ip
  // e.g. when the ip is ill formatted
  const auto ip_subnet = split(split(ip, '%').at(0), '/');
  const int version = get_af(ip_subnet.at(0));
  IP_address ipa;
  ipa.family = version;
  ipa.subnet = get_subnet(version, ip_subnet);
  inet_pton(version, ip_subnet.at(0).c_str(), &ipa.address.ipv6);
  return ipa;
}

std::string get_pure_ip(const IP_address &ip) { return ip.pure(); }

std::ostream &operator<<(std::ostream &out, const IP_address &ipa) {
  out << ipa.with_subnet();
  return out;
}
