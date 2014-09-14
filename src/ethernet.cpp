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
#include <sstream>
#include "container_utils.h"
#include "int_utils.h"

std::ostream& operator<<(std::ostream& out, const Link_layer& ll) {
        out << ll.get_info();
        return out;
}

std::string Linux_cooked_capture::source() const {
        std::vector<uint8_t> tmp_source_address(std::begin(source_address), std::begin(source_address) + ll_address_length);
        return join(tmp_source_address, one_byte_to_two_hex_chars, ":");
}

size_t Linux_cooked_capture::header_length() const {
        return 16;
}

uint16_t Linux_cooked_capture::payload_protocol() const {
        return payload_type;
}

std::string Linux_cooked_capture::get_info() const {
        return "Linux cooked capture: src: " + source();
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

std::string sniff_ethernet::destination() const {
        return join(ether_dhost, [](int i){return i;}, ":");
}

std::string sniff_ethernet::source() const {
        return join(ether_shost, [](int i){return i;}, ":");
}

std::string sniff_ethernet::get_info() const {
        return "Ethernet: dst = " + destination() + ", src = " + source();
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

std::vector<uint8_t> create_ethernet_header(const std::string& dmac, const std::string& smac, const std::string& type) {
        const std::string data = remove_seperator_from_mac(dmac) + remove_seperator_from_mac(smac) + type;
        return to_binary(data);
}

