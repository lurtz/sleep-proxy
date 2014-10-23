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

#include "../src/ip.h"

#include "packet_test_utils.h"

// TODO test ipv4 + udp
// TODO test ipv6 + tcp

// src 141.76.2.4 dst 10.38.4.225 tcp 20 bytes dont fragment
const std::string ipv4_wireshark = "45000562c8f740003306db478d4c02040a2604e1";
// src 10.38.4.225 dst 178.237.17.223 tcp 20 bytes dont fragment
const std::string ipv4_wireshark2 = "4500002ed9ee400040068d080a2604e1b2ed11df";
// Internet Protocol Version 6, Src: fe80::9863:12ff:fee1:3a3d (fe80::9863:12ff:fee1:3a3d), Dst: ff02::1 (ff02::1) udp 40 bytes
const std::string ipv6_wireshark = "60000000000c1101fe80000000000000986312fffee13a3dff020000000000000000000000000001";

class Ip_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Ip_test );
        CPPUNIT_TEST( test_ipv4_0 );
        CPPUNIT_TEST( test_ipv4_0_too_short );
        CPPUNIT_TEST( test_ipv4_1 );
        CPPUNIT_TEST( test_ipv4_1_too_short );
        CPPUNIT_TEST( test_ipv6_0 );
        CPPUNIT_TEST( test_ipv6_0_too_short );
        CPPUNIT_TEST( test_wrong_ip_version_ipv4 );
        CPPUNIT_TEST( test_wrong_ip_version_ipv6 );
        CPPUNIT_TEST( test_unknown_ip_version );
        CPPUNIT_TEST_SUITE_END();

        std::vector<uint8_t> ipv4_0;
        std::vector<uint8_t> ipv4_1;
        std::vector<uint8_t> ipv6_0;

        public:
        void setUp() {
                ipv4_0 = to_binary(ipv4_wireshark);
                ipv4_1 = to_binary(ipv4_wireshark2);
                ipv6_0 = to_binary(ipv6_wireshark);
        }

        void tearDown() {}

        void test_ipv4_0() {
                auto ip = parse_ip(ip::ipv4, std::begin(ipv4_0), std::end(ipv4_0) );
                test_ip(ip, ip::ipv4, "141.76.2.4/32", "10.38.4.225/32", 20, ip::TCP);
        }

        void test_ipv4_0_too_short() {
                CPPUNIT_ASSERT_THROW(parse_ip(ip::ipv4, std::begin(ipv4_0), std::end(ipv4_0)-1 ), std::length_error);
        }

        void test_ipv4_1() {
                auto ip = parse_ip(ip::ipv4, std::begin(ipv4_1), std::end(ipv4_1));
                test_ip(ip, ip::ipv4, "10.38.4.225/32", "178.237.17.223/32", 20, ip::TCP);
        }

        void test_ipv4_1_too_short() {
                CPPUNIT_ASSERT_THROW(parse_ip(ip::ipv4, std::begin(ipv4_1), std::end(ipv4_1)-1 ), std::length_error);
        }

        void test_ipv6_0() {
// Internet Protocol Version 6, Src: fe80::9863:12ff:fee1:3a3d (fe80::9863:12ff:fee1:3a3d), Dst: ff02::1 (ff02::1) udp 40 bytes
                auto ip = parse_ip(ip::ipv6, std::begin(ipv6_0), std::end(ipv6_0) );
                test_ip(ip, ip::ipv6, "fe80::9863:12ff:fee1:3a3d/128", "ff02::1/128", 40, ip::UDP);
        }

        void test_ipv6_0_too_short() {
                CPPUNIT_ASSERT_THROW(parse_ip(ip::ipv6, std::begin(ipv6_0), std::end(ipv6_0)-1 ), std::length_error);
        }

        void test_wrong_ip_version_ipv4 () {
                CPPUNIT_ASSERT(std::unique_ptr<ip>(nullptr) == parse_ip(ip::ipv6, std::begin(ipv4_0), std::end(ipv4_0)));
        }

        void test_wrong_ip_version_ipv6 () {
                CPPUNIT_ASSERT(std::unique_ptr<ip>(nullptr) == parse_ip(ip::ipv4, std::begin(ipv6_0), std::end(ipv6_0)));
        }

        void test_unknown_ip_version () {
                for (uint16_t i = 0; i < 20; i++) {
                        if (ip::ipv4 == i || ip::ipv6 == i)
                                continue;
                        CPPUNIT_ASSERT(std::unique_ptr<ip>(nullptr) == parse_ip(i, std::begin(ipv4_0), std::end(ipv4_0)));
                }
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Ip_test );

