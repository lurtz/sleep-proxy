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

#include "packet_parser.h"
#include "log.h"

template<typename T>
void print_if_not_nullptr(std::ostream& out, T&& ptr) {
        if (ptr != nullptr) {
                out << *ptr;
        }
}

std::ostream& operator<<(std::ostream& out, const basic_headers& headers) {
        print_if_not_nullptr(out, std::get<0>(headers));
        out << '\n';
        print_if_not_nullptr(out, std::get<1>(headers));
        return out;
}

basic_headers get_headers(const int type, const std::vector<u_char>& packet) {
        std::vector<u_char>::const_iterator data = std::begin(packet);
        std::vector<u_char>::const_iterator end = std::end(packet);

        // link layer header
        std::unique_ptr<Link_layer> ll = parse_link_layer(type, data, end);
        if (ll == nullptr) {
                log(LOG_ERR, "unsupported link layer protocol: %i", type);
                return std::make_tuple(std::unique_ptr<Link_layer>(nullptr), std::unique_ptr<ip>(nullptr));
        }
        std::advance(data, ll->header_length());

        // possible VLAN header, skip it
        uint16_t payload_type = ll->payload_protocol();
        if (payload_type == ETHERTYPE_VLAN) {
                std::unique_ptr<Link_layer> vlan_header = parse_link_layer(payload_type, data, end);
                payload_type = vlan_header->payload_protocol();
                std::advance(data, vlan_header->header_length());
        }

        // IP header
        std::unique_ptr<ip> ipp = parse_ip(payload_type, data, end);
        if (ipp == nullptr) {
                log(LOG_ERR, "unsupported link layer payload: %u", payload_type);
                return std::make_tuple(std::move(ll), std::unique_ptr<ip>(nullptr));
        }
        std::advance(data, ipp->header_length());

        return std::make_tuple(std::move(ll), std::move(ipp));
}

Catch_incoming_connection::Catch_incoming_connection(const int link_layer_typee) : link_layer_type(link_layer_typee) {}

void Catch_incoming_connection::operator()(const pcap_pkthdr * header, const u_char * packet) {
        if (header == nullptr || packet == nullptr) {
                log_string(LOG_ERR, "header or packet are nullptr");
                return;
        }
        data = std::vector<uint8_t>(packet, packet + header->len);
        headers = get_headers(link_layer_type, data);
}

