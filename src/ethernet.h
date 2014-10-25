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

#pragma once

#include <ostream>
#include <vector>
#include <array>
#include <arpa/inet.h>
#include <pcap/bpf.h>
#include <memory>
#include <netinet/ether.h>

struct Link_layer {

        template<typename iterator>
        Link_layer(iterator data, iterator end) {
                static_assert(std::is_same<typename iterator::value_type, uint8_t>::value, "container has to carry u_char or uint8_t");
                if (data >= end) {
                        throw std::range_error("data iterator past the end");
                }
        }

        virtual ~Link_layer() {}

        virtual size_t header_length() const = 0;

        virtual uint16_t payload_protocol() const = 0;

        virtual std::string get_info() const = 0;
};

std::ostream& operator<<(std::ostream& out, const Link_layer&);

struct Source_address {
        virtual ~Source_address() {}
        virtual ether_addr source() const = 0;
};

struct Linux_cooked_capture : public Link_layer, Source_address {
        private:
        uint16_t packet_type;
        uint16_t device_type;
        uint16_t ll_address_length;
        std::array<uint8_t, 8> source_address;
        uint16_t payload_type;

        public:
        template<typename iterator>
        Linux_cooked_capture(iterator data, iterator end) : Link_layer(data, end), source_address{{0}} {
                if (static_cast<size_t>(end - data) < header_length()) {
                        throw std::length_error("not enough data to construct an ethernet header");
                }
                packet_type = ntohs(*reinterpret_cast<uint16_t const *>(&(*data)));
                std::advance(data, 2);
                device_type = ntohs(*reinterpret_cast<uint16_t const *>(&(*data)));
                if (device_type != ARPHRD_ETHER) {
                        throw std::runtime_error("Linux_cooked_capture only supports ethernet");
                }
                std::advance(data, 2);
                ll_address_length = ntohs(*reinterpret_cast<uint16_t const *>(&(*data)));
                if (ll_address_length > source_address.size()) {
                        throw std::length_error("invalid link address size");
                }
                std::advance(data, 2);
                std::copy(data, data+ll_address_length, std::begin(source_address));
                std::advance(data, source_address.size());
                payload_type = ntohs(*reinterpret_cast<uint16_t const *>(&(*data)));
        }

        virtual ether_addr source() const;

        virtual size_t header_length() const;

        virtual uint16_t payload_protocol() const;

        virtual std::string get_info() const;
};

struct VLAN_Header : public Link_layer {
        private:
        uint16_t priority_canonical_id;
        uint16_t payload_type;
        public:
        template<typename iterator>
        VLAN_Header(iterator data, iterator end) : Link_layer(data, end) {
                if (static_cast<size_t>(end - data) < header_length()) {
                        throw std::length_error("not enough data to construct a vlan header");
                }
                priority_canonical_id = ntohs(*reinterpret_cast<uint16_t const *>(&(*data)));
                std::advance(data, 2);
                payload_type = ntohs(*reinterpret_cast<uint16_t const *>(&(*data)));
        }

        virtual size_t header_length() const;

        virtual uint16_t payload_protocol() const;

        virtual std::string get_info() const;
};

/** Ethernet header with destination address, source address and payload type */
struct sniff_ethernet : public Link_layer, Source_address {
        private:
        /* Destination host address */
        ether_addr ether_dhost;
        /* Source host address */
        ether_addr ether_shost;
        /* IP? ARP? RARP? etc */
        u_short ether_type;

        public:
        /**
         * constructs an ethernet header from data and checks using end that
         * enough bytes are present
         */
        template<typename iterator>
        sniff_ethernet(iterator data, iterator end) : Link_layer(data, end) {
                if (static_cast<size_t>(end - data) < header_length()) {
                        throw std::length_error("not enough data to construct an ethernet header");
                }
                std::copy(data, data+ETHER_ADDR_LEN, std::begin(ether_dhost.ether_addr_octet));
                std::advance(data, ETHER_ADDR_LEN);
                std::copy(data, data+ETHER_ADDR_LEN, std::begin(ether_shost.ether_addr_octet));
                std::advance(data, ETHER_ADDR_LEN);
                ether_type = ntohs(*reinterpret_cast<u_short const *>(&(*data)));
        }

        /**
         * size of an ethernet header
         */
        virtual size_t header_length() const;

        /**
         * which protocol is to expect next
         */
        virtual uint16_t payload_protocol() const;

        /**
         * destination address
         */
        ether_addr destination() const;

        /**
         * source address
         */
        virtual ether_addr source() const;

        virtual std::string get_info() const;
};

/** writes destination and source from eth into out */
std::ostream& operator<<(std::ostream& out, const sniff_ethernet& eth);

template<typename iterator>
std::unique_ptr<Link_layer> parse_link_layer(const int type, iterator data, iterator end) {
        switch (type) {
                case DLT_LINUX_SLL: return std::unique_ptr<Link_layer>(new Linux_cooked_capture(data, end));
                case DLT_EN10MB: return std::unique_ptr<Link_layer>(new sniff_ethernet(data, end));
                case ETHERTYPE_VLAN: return std::unique_ptr<Link_layer>(new VLAN_Header(data, end));
                default: return std::unique_ptr<Link_layer>(nullptr);
        }
}

std::vector<uint8_t> create_ethernet_header(const ether_addr& dmac, const ether_addr& smac, const uint16_t type);

std::vector<uint8_t> to_vector(const ether_addr& mac);

ether_addr mac_to_binary(const std::string& mac);

std::string binary_to_mac(const ether_addr& mac);
