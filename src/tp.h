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
#include <ostream>
#include <netinet/in.h>
#include <memory>
#include <vector>
#include <stdexcept>

/** abstract base class for transport protocols like TCP and UDP */
struct tp {
        enum Type {TCP = 6, UDP = 17};
        /**
         * perform sanity and bounds checks on data and end
         */
        template<typename iterator>
        tp(iterator data, iterator end) {
                static_assert(std::is_same<typename iterator::value_type, uint8_t>::value, "container has to carry u_char or uint8_t");
                if (data >= end) {
                        throw std::range_error("data iterator past the end");
                }
        }

        virtual ~tp() {}

        /** which type of transports protocol is it actually */
        virtual tp::Type type() const = 0;

        /** source port */
        virtual uint16_t source() const = 0;
        /** destination port */
        virtual uint16_t destination() const = 0;
        /** size of the header in bytes */
        virtual size_t header_length() const = 0;
        /** some extra information like set TCP flags */
        virtual std::string extra_info() const;
};

/** writes tp into out */
std::ostream& operator<<(std::ostream& out, const tp& tp);

/** TCP header */
struct sniff_tcp : public tp {
        typedef u_int tcp_seq;
        enum TCP_Flags {
                TH_FIN = 0x01,
                TH_SYN = 0x02,
                TH_RST = 0x04,
                TH_PUSH = 0x08,
                TH_ACK = 0x10,
                TH_URG = 0x20,
                TH_ECE = 0x40,
                TH_CWR = 0x80,
        };
        static const unsigned int TH_FLAGS = TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR;
        private:
        /** source port */
        u_short th_sport;
        /** destination port */
        u_short th_dport;
        /** sequence number */
        tcp_seq th_seq;
        /** acknowledgement number */
        tcp_seq th_ack;
        /** data offset, rsvd */
        u_char th_offx2;
        /** flags */
        u_char th_flags;
        /** window */
        u_short th_win;
        /** checksum */
        u_short th_sum;
        /** urgent pointer */
        u_short th_urp;

        public:
        /**
         * constructs a TCP header usind data and performing bounds checks
         * with end
         * */
        template<typename iterator>
        sniff_tcp(iterator data, iterator end) : tp(data, end) {
                const size_t databytes = static_cast<size_t>(end - data);
                if (databytes < 20) {
                        throw std::length_error("not enough data to construct a TCP header");
                }
                th_sport = ntohs(*reinterpret_cast<u_short const *>(&(*data)));
                std::advance(data, 2);
                th_dport = ntohs(*reinterpret_cast<u_short const *>(&(*data)));
                std::advance(data, 2);
                th_seq = ntohl(*reinterpret_cast<tcp_seq const *>(&(*data)));
                std::advance(data, 4);
                th_ack = ntohl(*reinterpret_cast<tcp_seq const *>(&(*data)));
                std::advance(data, 4);
                th_offx2 = *data;
                std::advance(data, 1);
                if (databytes < header_length()) {
                        throw std::length_error("not enough data to construct a TCP header");
                }
                th_flags = *data;
                std::advance(data, 1);
                th_win = ntohs(*reinterpret_cast<u_short const *>(&(*data)));
                std::advance(data, 2);
                th_sum = ntohs(*reinterpret_cast<u_short const *>(&(*data)));
                std::advance(data, 2);
                th_urp = ntohs(*reinterpret_cast<u_short const *>(&(*data)));
        }

        virtual size_t header_length() const;
        virtual tp::Type type() const;
        virtual uint16_t source() const;
        virtual uint16_t destination() const;
        virtual std::string extra_info() const;
};

/** UDP header */
struct sniff_udp : public tp {
        private:
        uint16_t source_port;
        uint16_t destination_port;
        uint16_t length;
        uint16_t checksum;

        public:
        /**
         * constructs a TCP header usind data and performing bounds checks
         * with end
         * */
        template<typename iterator>
        sniff_udp(iterator data, iterator end) : tp(data, end) {
                if (static_cast<size_t>(end - data) < header_length()) {
                        throw std::length_error("not enough data to construct a UDP header");
                }
                source_port = ntohs(*reinterpret_cast<uint16_t const *>(&(*data)));
                std::advance(data, 2);
                destination_port = ntohs(*reinterpret_cast<uint16_t const *>(&(*data)));
                std::advance(data, 2);
                length = ntohs(*reinterpret_cast<uint16_t const *>(&(*data)));
                std::advance(data, 2);
                checksum = ntohs(*reinterpret_cast<uint16_t const *>(&(*data)));
        }

        virtual tp::Type type() const;
        virtual uint16_t source() const;
        virtual uint16_t destination() const;
        virtual size_t header_length() const;
};

/**
 * create an TCP or UDP object depending on type from data and perform bounds
 * checks with end
 */
template<typename iterator>
std::unique_ptr<tp> parse_tp(uint8_t type, iterator data, iterator end) {
        switch(type) {
                case tp::Type::TCP: return std::unique_ptr<tp>(new sniff_tcp(data, end));
                case tp::Type::UDP: return std::unique_ptr<tp>(new sniff_udp(data, end));
                default: return std::unique_ptr<tp>(nullptr);
        }
}
