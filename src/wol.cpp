#include "wol.h"
#include <unistd.h>
#include <algorithm>
#include <arpa/inet.h>
#include "int_utils.h"
#include "socket.h"
#include "container_utils.h"
#include "log.h"

// TODO do much better assert with file and line info
void assert(const bool expr) {
        if (!expr) {
                throw std::runtime_error("assert failed");
        }
}

/**
 * converts two hex characters into a byte value
 */
uint8_t two_hex_chars_to_byte(char a, char b) {
        const long long int left = fallback::std::stoll(std::string(1, a), 16);
        const long long int right = fallback::std::stoll(std::string(1, b), 16);
        assert(left >= 0 && left < 16);
        assert(right >= 0 && right < 16);
        return static_cast<uint8_t>(left<<4) | static_cast<uint8_t>(right);
}

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

std::vector<uint8_t> to_binary(const std::string& hex) {
        std::vector<uint8_t> binary;
        for (auto iter = std::begin(hex); iter < std::end(hex); iter+= 2) {
                binary.push_back(two_hex_chars_to_byte(*iter, *(iter+1)));
        }
        return binary;
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

std::vector<uint8_t> create_ethernet_header(const std::string& dmac) {
        std::string data = remove_seperator_from_mac(dmac) + "FFFFFFFFFFFF" + "0842";
        return to_binary(data);
}

void wol_ethernet(const std::string& iface, const std::string& mac) {
        log_string(LOG_INFO, "waking (ethernet) " + mac);
        const std::vector<uint8_t> binary_data = create_ethernet_header(mac) + create_wol_udp_payload(mac);

        // Broadcast it to the LAN.
        Socket sock(AF_INET, SOCK_PACKET, SOCK_PACKET);
        sock.set_sock_opt(SOL_SOCKET, SO_BROADCAST, 1);
        sockaddr broadcast{PF_UNSPEC, {0}};
        assert(iface.size() <= sizeof(broadcast.sa_data));
        std::copy(std::begin(iface), std::end(iface), std::begin(broadcast.sa_data));
        sock.send_to(binary_data, 0, broadcast);
}

