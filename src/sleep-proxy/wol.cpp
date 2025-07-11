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

#include "wol.h"
#include "container_utils.h"
#include "ethernet.h"
#include "log.h"
#include "socket.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <algorithm>

std::vector<uint8_t> create_wol_payload(const ether_addr &mac) {
  const std::vector<uint8_t> binary_mac = to_vector(mac);
  static auto const mb = uint8_t{0xff};
  std::vector<uint8_t> magic_bytes{mb, mb, mb, mb, mb, mb};
  static auto const mac_repititions = uint8_t{16};
  for (unsigned int i = 0; i < mac_repititions; i++) {
    magic_bytes.insert(std::end(magic_bytes), std::begin(binary_mac),
                       std::end(binary_mac));
  }
  return magic_bytes;
}

Wol_method parse_wol_method(const std::string &readable_wol_method) {
  if (readable_wol_method == "ethernet") {
    return Wol_method::ethernet;
  }

  if (readable_wol_method == "udp") {
    return Wol_method::udp;
  }

  throw std::invalid_argument("invalid wol method: " + readable_wol_method);
}

std::ostream &operator<<(std::ostream &out, const Wol_method &wol_method) {
  switch (wol_method) {
  case Wol_method::ethernet:
    out << "ethernet";
    break;
  case Wol_method::udp:
    out << "udp";
    break;
  default:
    throw std::runtime_error("invalid wol method");
  }
  return out;
}

void wol_udp(const ether_addr &mac) {
  log_string(LOG_INFO, "waking (udp) " + binary_to_mac(mac));
  const std::vector<uint8_t> binary_data = create_wol_payload(mac);
  // Broadcast it to the LAN.
  Socket sock(AF_INET, SOCK_DGRAM);
  sock.set_sock_opt(SOL_SOCKET, SO_BROADCAST, 1);
  const sockaddr_in broadcast_port9{.sin_family = AF_INET,
                                    .sin_port = htons(9),
                                    .sin_addr = {INADDR_BROADCAST},
                                    .sin_zero = {0}};
  sock.send_to(binary_data, 0, broadcast_port9);
}

void wol_ethernet(const std::string &iface, const ether_addr &mac) {
  log_string(LOG_INFO, "waking (ethernet) " + binary_to_mac(mac));

  // Broadcast it to the LAN.
  Socket sock(PF_PACKET, SOCK_RAW, 0);
  sock.set_sock_opt(SOL_SOCKET, SO_BROADCAST, 1);

  sockaddr_ll broadcast_ll{.sll_family = 0,
                           .sll_protocol = 0,
                           .sll_ifindex = 0,
                           .sll_hatype = 0,
                           .sll_pkttype = 0,
                           .sll_halen = 0,
                           .sll_addr = {}};
  broadcast_ll.sll_family = AF_PACKET;
  broadcast_ll.sll_ifindex = sock.get_ifindex(iface);
  broadcast_ll.sll_halen = ETH_ALEN;
  const ether_addr hw_addr = sock.get_hwaddr(iface);
  std::ranges::copy(hw_addr.ether_addr_octet,

                    std::begin(broadcast_ll.sll_addr));

  const std::vector<uint8_t> binary_data =
      create_ethernet_header(mac, hw_addr, 0x0842) + create_wol_payload(mac);
  sock.send_to(binary_data, 0, broadcast_ll);
}
