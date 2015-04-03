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
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include "int_utils.h"
#include "socket.h"
#include "container_utils.h"
#include "log.h"
#include "ethernet.h"

/**
 * create the payload for a UDP wol packet to be broadcast in to the network
 */
std::vector<uint8_t> create_wol_udp_payload(const ether_addr &mac) {
  const std::vector<uint8_t> binary_mac = to_vector(mac);
  std::vector<uint8_t> magic_bytes{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  for (unsigned int i = 0; i < 20; i++) {
    magic_bytes.insert(std::end(magic_bytes), std::begin(binary_mac),
                       std::end(binary_mac));
  }
  return magic_bytes;
}

/**
 * Send a WOL UDP packet to the given mac
 */
void wol_udp(const ether_addr &mac) {
  log_string(LOG_INFO, "waking (udp) " + binary_to_mac(mac));
  const std::vector<uint8_t> binary_data = create_wol_udp_payload(mac);
  // Broadcast it to the LAN.
  Socket sock(AF_INET, SOCK_DGRAM);
  sock.set_sock_opt(SOL_SOCKET, SO_BROADCAST, 1);
  const sockaddr_in broadcast_port9{AF_INET, htons(9), {INADDR_BROADCAST}, {0}};
  sock.send_to(binary_data, 0, broadcast_port9);
}

void wol_ethernet(const std::string &iface, const ether_addr &mac) {
  log_string(LOG_INFO, "waking (ethernet) " + binary_to_mac(mac));

  // Broadcast it to the LAN.
  Socket sock(PF_PACKET, SOCK_RAW, 0);
  sock.set_sock_opt(SOL_SOCKET, SO_BROADCAST, 1);

  sockaddr_ll broadcast_ll{0, 0, 0, 0, 0, 0, {0}};
  broadcast_ll.sll_family = AF_PACKET;
  broadcast_ll.sll_ifindex = sock.get_ifindex(iface);
  broadcast_ll.sll_halen = ETH_ALEN;
  const ether_addr hw_addr = sock.get_hwaddr(iface);
  std::copy(std::begin(hw_addr.ether_addr_octet),
            std::end(hw_addr.ether_addr_octet), broadcast_ll.sll_addr);

  const std::vector<uint8_t> binary_data =
      create_ethernet_header(mac, hw_addr, 0x0842) +
      create_wol_udp_payload(mac);
  sock.send_to(binary_data, 0, broadcast_ll);
}
