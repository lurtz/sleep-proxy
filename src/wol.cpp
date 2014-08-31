#include "wol.h"
#include <unistd.h>
#include <algorithm>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include "int_utils.h"
#include "socket.h"
#include "container_utils.h"
#include "log.h"
#include "pcap_wrapper.h"

std::string remove_seperator_from_mac(const std::string& mac) {
        if (mac.size() != 12 && mac.size() != 12+5) {
                throw std::runtime_error("Incorrect MAC address format");
        }
        // check macaddress format and try to compensate
        std::string rawmac(12, '0');
        char sep = mac[2];
        if (mac.size() == 12) {
                sep = -1;
        }
        std::copy_if(std::begin(mac), std::end(mac), std::begin(rawmac), [&](char ch) {return ch != sep;});
        return rawmac;
}

/**
 * create the payload for a UDP wol packet to be broadcast in to the network
 */
std::vector<uint8_t> create_wol_udp_payload(const std::string& mac) {
        std::string rawmac = remove_seperator_from_mac(mac);
        // pad the synchronization stream
        std::string data = repeat<std::string>(rawmac, 20, "FFFFFFFFFFFF");
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

template<typename T, typename Alloc>
std::vector<T, Alloc> operator+(std::vector<T, Alloc>&& lhs, const std::vector<T, Alloc>& rhs) {
        lhs.insert(std::end(lhs), std::begin(rhs), std::end(rhs));
        return lhs;
}

std::vector<uint8_t> create_ethernet_header(const std::string& dmac, const std::string& smac) {
        std::string data = remove_seperator_from_mac(dmac) + remove_seperator_from_mac(smac) + "0842";
        return to_binary(data);
}

void wol_ethernet_pcap(const std::string& iface, const std::string& mac) {
        log_string(LOG_INFO, "waking (ethernet) " + mac);
        Socket sock(PF_PACKET, SOCK_RAW, 0);
        const std::string hw_addr = to_hex(sock.get_hwaddr(iface));
        const std::vector<uint8_t> binary_data = create_ethernet_header(mac, hw_addr) + create_wol_udp_payload(mac);

        Pcap_wrapper pcap(iface);
        pcap.inject(binary_data);
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

        const std::vector<uint8_t> binary_data = create_ethernet_header(mac, to_hex(hw_addr)) + create_wol_udp_payload(mac);
        sock.send_to(binary_data, 0, broadcast_ll);
}

