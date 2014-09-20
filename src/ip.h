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

#include <string>
#include <arpa/inet.h>
#include <memory>
#include <vector>
#include <stdexcept>
#include "log.h"

/** Abstract base class for any IP version */
struct ip {
        enum Version {ipv4 = 0x800, ipv6 = 0x86DD};
        /**
         * Constructs nothing. Checks if data < end and the data consists
         * of bytes
         */
        template<typename iterator>
        ip(iterator data, iterator end) {
                static_assert(std::is_same<typename iterator::value_type, uint8_t>::value, "container has to carry u_char or uint8_t");
                if (data >= end) {
                        throw std::range_error("data iterator past the end");
                }
        }

        virtual ~ip() {}

        /** which IP version */
        virtual Version version() const = 0;

        /** length of IP header in bytes */
        virtual size_t header_length() const = 0;

        /** source address */
        virtual std::string source() const = 0;

        /** destination address */
        virtual std::string destination() const = 0;

        /** which protocol header to expect next */
        virtual uint8_t payload_protocol() const = 0;
};

/** writes ip into out which every information available to the base class */
std::ostream& operator<<(std::ostream& out, const ip& ip);

/**
 * IPv4 header
 */
struct sniff_ipv4 : public ip {
        enum IP_Flags {
                IP_RF = 0x8000,      /* reserved fragment flag */
                IP_DF = 0x4000,      /* dont fragment flag */
                IP_MF = 0x2000,      /* more fragments flag */
                IP_OFFMASK = 0x1fff  /* mask for fragmenting bits */
        };
        private:
        /** version << 4 | header length >> 2 */
        u_char ip_vhl;
        /** type of service */
        u_char ip_tos;
        /** total length */
        u_short ip_len;
        /** identification */
        u_short ip_id;
        /** fragment offset field */
        u_short ip_off;
        /** time to live */
        u_char ip_ttl;
        /** protocol */
        u_char ip_p;
        /** checksum */
        u_short ip_sum;
        /** source and dest address */
        struct in_addr ip_src,ip_dst;

        public:
        /**
         * Constructs an IPv4 header from data. Using end checks are performed
         * if enough data is present
         */
        template<typename iterator>
        sniff_ipv4(iterator data, iterator end) : ip(data, end) {
                ip_vhl = *(data++);
                const uint8_t version = ip_vhl >> 4;
                if (version != 4) {
                        throw std::runtime_error("while parsing ipv4, got wrong ip version: " + to_string(version));
                }
                if (data >= end) {
                        throw std::range_error("data iterator past the end");
                }
                if (header_length() - 1 > static_cast<size_t>(end - data)) {
                        throw std::length_error("not enough data to construct an IPv4 header");
                }
                ip_tos = *(data++);
                ip_len = ntohs(*reinterpret_cast<u_short const *>(&(*(data++))));
                data++;
                ip_id = ntohs(*reinterpret_cast<u_short const *>(&(*(data++))));
                data++;
                ip_off = ntohs(*reinterpret_cast<u_short const *>(&(*(data++))));
                data++;
                ip_ttl = *(data++);
                ip_p = *(data++);
                ip_sum = ntohs(*reinterpret_cast<u_short const *>(&(*(data++))));
                data++;
                ip_src = *reinterpret_cast<in_addr const *>(&(*(data++)));
                data += 3;
                ip_dst = *reinterpret_cast<in_addr const *>(&(*(data++)));
        }

        virtual ip::Version version() const;
        virtual size_t header_length() const;
        virtual std::string source() const;
        virtual std::string destination() const;
        virtual uint8_t payload_protocol() const;
};

/** IPv6 header */
struct sniff_ipv6 : public ip {
        private:
        uint32_t version_trafficclass_flowlabel;
        /** size of the payload */
        uint16_t payload_length;
        /** type of the following protocol */
        uint8_t next_header;
        /** maximum number of nodes to pass */
        uint8_t hop_limit;
        in6_addr source_address;
        in6_addr dest_address;

        public:
        /**
         * Constructs an IPv6 header using data. with end bounds checks are
         * performed to make sure that enough data exists
         */
        template<typename iterator>
        sniff_ipv6(iterator data, iterator end) : ip(data, end) {
                if (static_cast<size_t>(end - data) < header_length()) {
                        throw std::length_error("not enough data to construct an IPv6 header");
                }
                version_trafficclass_flowlabel = ntohl(*reinterpret_cast<uint32_t const *>(&(*(data++))));
                const uint8_t version = version_trafficclass_flowlabel >> 28;
                if (version != 6) {
                        throw std::runtime_error("parsing ipv6 header, got wrong ip version: " + to_string(version));
                }
                data += 3;
                payload_length = ntohs(*reinterpret_cast<uint16_t const *>(&(*(data++))));
                data++;
                next_header = *(data++);
                hop_limit = *(data++);
                std::copy(data, data+16, source_address.s6_addr);
                data += 16;
                std::copy(data, data+16, dest_address.s6_addr);
        }
        virtual ip::Version version() const;
        virtual size_t header_length() const;
        virtual std::string source() const;
        virtual std::string destination() const;
        uint32_t traffic_class() const;
        uint32_t flow_label() const;
        virtual uint8_t payload_protocol() const;
};

/**
 * using type as a hint and to perform validity checks parse an IPv4/IPv6
 * header from data and perform bounds check with end
 */
template<typename iterator>
std::unique_ptr<ip> parse_ip(uint16_t type, iterator data, iterator end) {
        uint8_t version = *data >> 4;
        // check wether type and the version the ip headers matches
        if ((type == ip::Version::ipv4 && version != 4) || (type == ip::Version::ipv6 && version != 6)) {
                log_string(LOG_ERR, "ethernet type and ip version do not match");
                return std::unique_ptr<ip>(nullptr);
        }
        // construct the IPv4/IPv6 header
        switch (type) {
                case ip::Version::ipv4: return std::unique_ptr<ip>(new sniff_ipv4(data, end));
                case ip::Version::ipv6: return std::unique_ptr<ip>(new sniff_ipv6(data, end));
                // do not know the IP version which is given
                default: return std::unique_ptr<ip>(nullptr);
        }
}
