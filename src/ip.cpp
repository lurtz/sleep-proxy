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
#include <arpa/inet.h>
#include "to_string.h"

std::ostream& operator<<(std::ostream& out, const in_addr& ip) {
        char addr[INET6_ADDRSTRLEN];
        out << inet_ntop(AF_INET, &(ip.s_addr), addr, INET6_ADDRSTRLEN);
        return out;
}

std::ostream& operator<<(std::ostream& out, const in6_addr& ip) {
        char addr[INET6_ADDRSTRLEN];
        out << inet_ntop(AF_INET6, ip.s6_addr, addr, INET6_ADDRSTRLEN);
        return out;
}

std::ostream& operator<<(std::ostream& out, const ip::Version& v) {
        switch (v) {
                case ip::Version::ipv4:
                        out << 4;
                        break;
                case ip::Version::ipv6:
                        out << 6;
                        break;
        }
        return out;
}

std::ostream& operator<<(std::ostream& out, const ip& ip) {
        out << "IPv" << ip.version() << ": ";
        out << "dst = " << ip.destination().pure() << ", src = " << ip.source().pure() << ", ";
        return out;
}

ip::Version sniff_ipv4::version() const {
        return Version::ipv4;
}

size_t sniff_ipv4::header_length() const {
        return (ip_vhl & 0x0f) * 4;
}
IP_address sniff_ipv4::source() const {
        return IP_address{AF_INET, {ip_src}, 32};
}
IP_address sniff_ipv4::destination() const {
        return IP_address{AF_INET, {ip_dst}, 32};
}
uint8_t sniff_ipv4::payload_protocol() const {
        return ip_p;
}

ip::Version sniff_ipv6::version() const {
        return Version::ipv6;
}
size_t sniff_ipv6::header_length() const {
        return 40;
}

IP_address get_ipv6_address(const in6_addr& addr) {
        IP_address ipa;
        ipa.family = AF_INET6;
        ipa.address.ipv6 = addr;
        ipa.subnet = 128;
        return ipa;
}

IP_address sniff_ipv6::source() const {
        return get_ipv6_address(source_address);
}

IP_address sniff_ipv6::destination() const {
        return get_ipv6_address(dest_address);
}

uint8_t sniff_ipv6::payload_protocol() const {
        return next_header;
}

