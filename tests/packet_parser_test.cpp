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

std::string ethernet_ipv4_tcp_wireshark = "00000000000000000000000008004500003c88d040004006b3e97f0000017f000001b5804e20b196b7ea00000000a002aaaafe3000000204ffd70402080a01793f3a0000000001030307";

std::string ethernet_ipv6_tcp_wireshark =   "00000000000000000000000086dd60000000002806400000000000000000000000000000000100000000000000000000000000000001e54f30394935bc9c00000000a002aaaa003000000204ffc40402080a03376fed0000000001030307";

void check_range(const long long int val, const long long int lower, const long long int upper) {
        if (val < lower || val >= upper) {
                throw std::out_of_range(to_string(val) + " is not in range [" + to_string(lower) + "," + to_string(upper) + ")");
        }
}

/**
 * converts two hex characters into a byte value
 */
uint8_t two_hex_chars_to_byte(const char a, const char b) {
        const long long int left = fallback::std::stoll(std::string(1, a), 16);
        const long long int right = fallback::std::stoll(std::string(1, b), 16);
        check_range(left, 0, 16);
        check_range(right, 0, 16);
        return static_cast<uint8_t>(left<<4) | static_cast<uint8_t>(right);
}

std::vector<uint8_t> to_binary(const std::string& hex) {
        std::vector<uint8_t> binary;
        for (auto iter = std::begin(hex); iter < std::end(hex)-1; iter+= 2) {
                binary.push_back(two_hex_chars_to_byte(*iter, *(iter+1)));
        }
        return binary;
}

void test_ip(const std::unique_ptr<ip>& ip, const ip::Version v, const std::string& src, const std::string& dst, const size_t header_length, const tp::Type pl_type) {

        CPPUNIT_ASSERT(ip != nullptr);
        CPPUNIT_ASSERT_EQUAL(v, ip->version());
        CPPUNIT_ASSERT_EQUAL(parse_ip(src), ip->source());
        CPPUNIT_ASSERT_EQUAL(parse_ip(dst), ip->destination());
        CPPUNIT_ASSERT_EQUAL(static_cast<uint8_t>(pl_type), ip->payload_protocol());
        CPPUNIT_ASSERT_EQUAL(header_length, ip->header_length());
}

void test_tp(const std::unique_ptr<tp>& tp, const tp::Type type, const uint16_t src, const uint16_t dst, const size_t size, const std::string& info) {
        CPPUNIT_ASSERT(tp != nullptr);
        CPPUNIT_ASSERT_EQUAL(type, tp->type());
        CPPUNIT_ASSERT_EQUAL(src, tp->source());
        CPPUNIT_ASSERT_EQUAL(dst, tp->destination());
        CPPUNIT_ASSERT_EQUAL(size, tp->header_length());
        CPPUNIT_ASSERT_EQUAL(info, tp->extra_info());
}

void test_ll(const std::unique_ptr<Link_layer>& ll, const size_t length, const ip::Version payload_protocol, const std::string& info) {
        CPPUNIT_ASSERT(ll != nullptr);
        CPPUNIT_ASSERT_EQUAL(length, ll->header_length());
        CPPUNIT_ASSERT_EQUAL(static_cast<uint16_t>(payload_protocol), ll->payload_protocol());
        CPPUNIT_ASSERT_EQUAL(info, ll->get_info());
}

void test_ethernet(const std::unique_ptr<Link_layer>& ll, const std::string& src, const std::string& dst) {
        const sniff_ethernet& ether = dynamic_cast<const sniff_ethernet&>(*ll);
        CPPUNIT_ASSERT_EQUAL(dst, binary_to_mac(ether.destination()));
        CPPUNIT_ASSERT_EQUAL(src, binary_to_mac(ether.source()));
}

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

                test_ip(std::get<1>(headers), ip::ipv4, "127.0.0.1/32", "127.0.0.1/32", 20, tp::TCP);

                test_tp(std::get<2>(headers), tp::TCP, 46464, 20000, 40, "Flags: SYN");
        }

        void test_parse_ethernet_ipv6_tcp() {
                auto headers = get_headers(DLT_EN10MB, ethernet_ipv6_tcp);

                auto& ll = std::get<0>(headers);
                test_ll(ll, 14, ip::ipv6, "Ethernet: dst = 0:0:0:0:0:0, src = 0:0:0:0:0:0");
                test_ethernet(ll, "0:0:0:0:0:0", "0:0:0:0:0:0");

                test_ip(std::get<1>(headers), ip::ipv6, "::1/128", "::1/128", 40, tp::TCP);

                test_tp(std::get<2>(headers), tp::TCP, 58703, 12345, 40, "Flags: SYN");
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Packet_parser_test );

