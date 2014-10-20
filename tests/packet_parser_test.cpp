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

#include "main.h"
#include <string>

#include "../src/packet_parser.h"
#include "../src/ethernet.h"
#include "../src/container_utils.h"
#include "../src/int_utils.h"

#include "packet_test_utils.h"

std::string ethernet_ipv4_tcp_wireshark = "00000000000000000000000008004500003c88d040004006b3e97f0000017f000001b5804e20b196b7ea00000000a002aaaafe3000000204ffd70402080a01793f3a0000000001030307";

std::string ethernet_ipv6_tcp_wireshark =   "00000000000000000000000086dd60000000002806400000000000000000000000000000000100000000000000000000000000000001e54f30394935bc9c00000000a002aaaa003000000204ffc40402080a03376fed0000000001030307";

class Packet_parser_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Packet_parser_test );
        CPPUNIT_TEST( test_parse_ethernet_ipv4_tcp );
        CPPUNIT_TEST( test_parse_ethernet_ipv6_tcp );
        CPPUNIT_TEST_SUITE_END();

        std::vector<uint8_t> ethernet_ipv4_tcp;
        std::vector<uint8_t> ethernet_ipv6_tcp;
        public:
        void setUp() {
                ethernet_ipv4_tcp = to_binary(ethernet_ipv4_tcp_wireshark);
                ethernet_ipv6_tcp = to_binary(ethernet_ipv6_tcp_wireshark);
        }

        void tearDown() {}

        void test_parse_ethernet_ipv4_tcp() {
                auto headers = get_headers(DLT_EN10MB, ethernet_ipv4_tcp);

                auto& ll = std::get<0>(headers);
                test_ll(ll, 14, ip::ipv4, "Ethernet: dst = 0:0:0:0:0:0, src = 0:0:0:0:0:0");
                test_ethernet(ll, "0:0:0:0:0:0", "0:0:0:0:0:0");

                test_ip(std::get<1>(headers), ip::ipv4, "127.0.0.1/32", "127.0.0.1/32", 20, ip::TCP);
        }

        void test_parse_ethernet_ipv6_tcp() {
                auto headers = get_headers(DLT_EN10MB, ethernet_ipv6_tcp);

                auto& ll = std::get<0>(headers);
                test_ll(ll, 14, ip::ipv6, "Ethernet: dst = 0:0:0:0:0:0, src = 0:0:0:0:0:0");
                test_ethernet(ll, "0:0:0:0:0:0", "0:0:0:0:0:0");

                test_ip(std::get<1>(headers), ip::ipv6, "::1/128", "::1/128", 40, ip::TCP);
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Packet_parser_test );

