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

// src 141.76.2.4 dst 10.38.4.225 tcp 20 bytes dont fragment
const std::string ipv4_tcp_wireshark =
    "45000562c8f740003306db478d4c02040a2604e1";
// src 10.38.4.225 dst 178.237.17.223 tcp 20 bytes dont fragment
const std::string ipv4_tcp_wireshark2 =
    "4500002ed9ee400040068d080a2604e1b2ed11df";
// Internet Protocol Version 4, Src: 192.168.1.198, Dst: 146.66.152.13 20 bytes
const std::string ipv4_udp_wireshark =
    "450000708dc640004011bff8c0a801c69242980d";
// Internet Protocol Version 6, Src: fe80::9863:12ff:fee1:3a3d
// (fe80::9863:12ff:fee1:3a3d), Dst: ff02::1 (ff02::1) udp 40 bytes
const std::string ipv6_udp_wireshark = "60000000000c1101fe80000000000000986312f"
                                       "ffee13a3dff0200000000000000000000000000"
                                       "01";
// Internet Protocol Version 6, Src: 2a03:2880:2110:6f07:face:b00c:0:1, Dst:
// 2001:470:1f15:ea7:a288:b4ff:fecf:5094
const std::string ipv6_tcp_wireshark = "68000000004f06312a03288021106f07faceb00"
                                       "c00000001200104701f150ea7a288b4fffecf50"
                                       "94";

class Ip_test : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(Ip_test);
  CPPUNIT_TEST(test_ipv4_tcp_0);
  CPPUNIT_TEST(test_ipv4_tcp_0_too_short);
  CPPUNIT_TEST(test_ipv4_tcp_1);
  CPPUNIT_TEST(test_ipv4_tcp_1_too_short);
  CPPUNIT_TEST(test_ipv4_udp);
  CPPUNIT_TEST(test_ipv6_udp);
  CPPUNIT_TEST(test_ipv6_udp_too_short);
  CPPUNIT_TEST(test_ipv6_tcp);
  CPPUNIT_TEST(test_wrong_ip_version_ipv4);
  CPPUNIT_TEST(test_wrong_ip_version_ipv6);
  CPPUNIT_TEST(test_unknown_ip_version);
  CPPUNIT_TEST_SUITE_END();

  const std::vector<uint8_t> ipv4_tcp_0 = to_binary(ipv4_tcp_wireshark);
  const std::vector<uint8_t> ipv4_tcp_1 = to_binary(ipv4_tcp_wireshark2);
  const std::vector<uint8_t> ipv4_udp = to_binary(ipv4_udp_wireshark);
  const std::vector<uint8_t> ipv6_udp = to_binary(ipv6_udp_wireshark);
  const std::vector<uint8_t> ipv6_tcp = to_binary(ipv6_tcp_wireshark);

public:
  void test_ipv4_tcp_0() {
    auto ip = parse_ip(ip::ipv4, std::begin(ipv4_tcp_0), std::end(ipv4_tcp_0));
    test_ip(ip, ip::ipv4, "141.76.2.4/32", "10.38.4.225/32", 20, ip::TCP);
  }

  void test_ipv4_tcp_0_too_short() {
    CPPUNIT_ASSERT_THROW(
        parse_ip(ip::ipv4, std::begin(ipv4_tcp_0), std::end(ipv4_tcp_0) - 1),
        std::length_error);
  }

  void test_ipv4_tcp_1() {
    auto ip = parse_ip(ip::ipv4, std::begin(ipv4_tcp_1), std::end(ipv4_tcp_1));
    test_ip(ip, ip::ipv4, "10.38.4.225/32", "178.237.17.223/32", 20, ip::TCP);
  }

  void test_ipv4_tcp_1_too_short() {
    CPPUNIT_ASSERT_THROW(
        parse_ip(ip::ipv4, std::begin(ipv4_tcp_1), std::end(ipv4_tcp_1) - 1),
        std::length_error);
  }

  void test_ipv4_udp() {
    auto ip = parse_ip(ip::ipv4, std::begin(ipv4_udp), std::end(ipv4_udp));
    test_ip(ip, ip::ipv4, "192.168.1.198/32", "146.66.152.13/32", 20, ip::UDP);
  }

  void test_ipv6_udp() {
    auto ip = parse_ip(ip::ipv6, std::begin(ipv6_udp), std::end(ipv6_udp));
    test_ip(ip, ip::ipv6, "fe80::9863:12ff:fee1:3a3d/128", "ff02::1/128", 40,
            ip::UDP);
  }

  void test_ipv6_tcp() {
    auto ip = parse_ip(ip::ipv6, std::begin(ipv6_tcp), std::end(ipv6_tcp));
    test_ip(ip, ip::ipv6, "2a03:2880:2110:6f07:face:b00c:0:1/128",
            "2001:470:1f15:ea7:a288:b4ff:fecf:5094/128", 40, ip::TCP);
  }

  void test_ipv6_udp_too_short() {
    CPPUNIT_ASSERT_THROW(
        parse_ip(ip::ipv6, std::begin(ipv6_udp), std::end(ipv6_udp) - 1),
        std::length_error);
  }

  void test_wrong_ip_version_ipv4() {
    CPPUNIT_ASSERT(
        std::unique_ptr<ip>(nullptr) ==
        parse_ip(ip::ipv6, std::begin(ipv4_tcp_0), std::end(ipv4_tcp_0)));
  }

  void test_wrong_ip_version_ipv6() {
    CPPUNIT_ASSERT(
        std::unique_ptr<ip>(nullptr) ==
        parse_ip(ip::ipv4, std::begin(ipv6_udp), std::end(ipv6_udp)));
  }

  void test_unknown_ip_version() {
    for (uint16_t i = 0; i < 20; i++) {
      if (ip::ipv4 == i || ip::ipv6 == i)
        continue;
      CPPUNIT_ASSERT(std::unique_ptr<ip>(nullptr) ==
                     parse_ip(i, std::begin(ipv4_tcp_0), std::end(ipv4_tcp_0)));
    }
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(Ip_test);
