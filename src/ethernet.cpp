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
#include <iterator>
#include <stdexcept>
#include "int_utils.h"

std::ostream& operator<<(std::ostream& out, const Link_layer& ll) {
        out << ll.get_info();
        return out;
}

Generic_Link_layer::Generic_Link_layer(size_t const header_length, ether_addr const source, uint16_t const payload_protocol, std::string const info) : m_header_length(header_length), m_source(source), m_payload_protocol(payload_protocol), m_info(info) {}


size_t Generic_Link_layer::header_length() const {
        return m_header_length;
}

uint16_t Generic_Link_layer::payload_protocol() const {
        return m_payload_protocol;
}

std::string Generic_Link_layer::get_info() const {
        return m_info;
}

ether_addr Generic_Link_layer::source() const {
        return m_source;
}

ether_addr Linux_cooked_capture::source() const {
        ether_addr addr;
        std::copy(std::begin(source_address), std::begin(source_address) + sizeof(addr.ether_addr_octet), std::begin(addr.ether_addr_octet));
        return addr;
}

size_t Linux_cooked_capture::header_length() const {
        return 16;
}

uint16_t Linux_cooked_capture::payload_protocol() const {
        return payload_type;
}

std::string Linux_cooked_capture::get_info() const {
        return "Linux cooked capture: src: " + binary_to_mac(source());
}


size_t VLAN_Header::header_length() const {
        return 4;
}

uint16_t VLAN_Header::payload_protocol() const {
        return payload_type;
}

std::string VLAN_Header::get_info() const {
        return "VLAN Header";
}

size_t sniff_ethernet::header_length() const {
        return 14;
}

uint16_t sniff_ethernet::payload_protocol() const {
        return ether_type;
}

ether_addr sniff_ethernet::destination() const {
        return ether_dhost;
}

ether_addr sniff_ethernet::source() const {
        return ether_shost;
}

std::string sniff_ethernet::get_info() const {
        return "Ethernet: dst = " + binary_to_mac(destination()) + ", src = " + binary_to_mac(source());
}

std::vector<uint8_t> to_vector(const ether_addr& mac) {
        return std::vector<uint8_t>(mac.ether_addr_octet, mac.ether_addr_octet+sizeof(mac.ether_addr_octet));
}

std::vector<uint8_t> create_ethernet_header(const ether_addr& dmac, const ether_addr& smac, const uint16_t type) {
        auto binary = to_vector(dmac) + to_vector(smac);
        binary.push_back(type >> 8);
        binary.push_back(type & 0xFF);
        return binary;
}

ether_addr mac_to_binary(const std::string& mac) {
        ether_addr addr{{0}};
        if (ether_aton_r(mac.c_str(), &addr) == nullptr) {
                throw std::runtime_error("invalid mac: " + mac);
        }
        return addr;
}

std::string binary_to_mac(const ether_addr& mac) {
        char canon_mac[12+5+1] = {0};
        if (ether_ntoa_r(&mac, canon_mac) == nullptr) {
                throw std::runtime_error("could convert binary to hex mac");
        }
        return canon_mac;
}

