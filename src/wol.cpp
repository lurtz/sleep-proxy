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
std::vector<uint8_t> create_wol_udp_payload(const std::string& mac) {
        const std::string rawmac = remove_seperator_from_mac(mac);
        // pad the synchronization stream
        const std::string data = repeat<std::string>(rawmac, 20, "FFFFFFFFFFFF");
        // convert chars to binary data
        return to_binary(data);
}

/**
 * Send a WOL UDP packet to the given mac
 */
void wol_udp(const std::string& mac) {
        log_string(LOG_INFO, "waking (udp) " + mac);
        const std::vector<uint8_t> binary_data = create_wol_udp_payload(mac);
        // Broadcast it to the LAN.
        Socket sock(AF_INET, SOCK_DGRAM);
        sock.set_sock_opt(SOL_SOCKET, SO_BROADCAST, 1);
        const sockaddr_in broadcast_port9{AF_INET, htons(9), {INADDR_BROADCAST}, {0}};
        sock.send_to(binary_data, 0, broadcast_port9);
}

void wol_ethernet(const std::string& iface, const std::string& mac) {
        log_string(LOG_INFO, "waking (ethernet) " + mac);

        // Broadcast it to the LAN.
        Socket sock(PF_PACKET, SOCK_RAW, 0);
        sock.set_sock_opt(SOL_SOCKET, SO_BROADCAST, 1);

        sockaddr_ll broadcast_ll{0, 0, 0, 0, 0, 0, {0}};
        broadcast_ll.sll_family = AF_PACKET;
        broadcast_ll.sll_ifindex = sock.get_ifindex(iface);
        broadcast_ll.sll_halen = ETH_ALEN;
        const std::vector<uint8_t> hw_addr = sock.get_hwaddr(iface);
        std::copy(std::begin(hw_addr), std::end(hw_addr), broadcast_ll.sll_addr);

        const std::vector<uint8_t> binary_data = create_ethernet_header(mac, to_hex(hw_addr), "0842") + create_wol_udp_payload(mac);
        sock.send_to(binary_data, 0, broadcast_ll);
}

