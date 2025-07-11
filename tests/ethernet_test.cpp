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

#include "packet_test_utils.h"

#include <cppunit/extensions/HelperMacros.h>

const std::string lcc_not_supported_ipv4_0_wireshark =
    "00000305000600000000000000000800";
const std::string lcc_loopback_ipv4_0_wireshark =
    "00000304000600000000000000000800";
const std::string ethernet_ipv4_0_wireshark = "0000000000000000000000000800";
const std::string ethernet_ipv4_1_wireshark = "1102330455060a0b0c0d0e0f0800";
const std::string ethernet_ipv6_0_wireshark = "00000000000000000000000086dd";
const std::string lcc_ipv4_0_wireshark = "00000001000600000000000000000800";
const std::string lcc_ipv4_1_wireshark = "00000001000660606060606000000800";
const std::string lcc_ipv4_2_wireshark = "00000001000860606060606012340800";
const std::string lcc_ipv4_3_wireshark = "00000001000960606060606000000800";
const std::string lcc_ipv6_0_wireshark = "000000010006616263646566000086dd";
const std::string vlan_ipv4_wireshark = "00010800";
const std::string vlan_ipv6_wireshark = "000186dd";
static auto const byte_size = 8;
static auto const byte_mask = 0xFF;

class Ethernet_test : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(Ethernet_test);
  CPPUNIT_TEST(test_parse_lcc_not_supported);
  CPPUNIT_TEST(test_parse_lcc_loopback);
  CPPUNIT_TEST(test_parse_lcc_ipv4);
  CPPUNIT_TEST(test_parse_lcc_ipv4_too_short);
  CPPUNIT_TEST(test_parse_lcc_ipv4_1);
  CPPUNIT_TEST(test_parse_lcc_ipv4_2);
  CPPUNIT_TEST(test_parse_lcc_ipv4_3);
  CPPUNIT_TEST(test_parse_lcc_ipv6);
  CPPUNIT_TEST(test_parse_ethernet_ipv4);
  CPPUNIT_TEST(test_parse_ethernet_ipv4_1);
  CPPUNIT_TEST(test_parse_ethernet_ipv6);
  CPPUNIT_TEST(test_parse_ethernet_ipv4_too_short);
  CPPUNIT_TEST(test_parse_ethernet_ipv6_too_short);
  CPPUNIT_TEST(test_parse_vlan_ipv4);
  CPPUNIT_TEST(test_parse_vlan_ipv6);
  CPPUNIT_TEST(test_parse_vlan_ipv4_too_short);
  CPPUNIT_TEST(test_parse_vlan_ipv6_too_short);
  CPPUNIT_TEST(test_create_ethernet_header_1);
  CPPUNIT_TEST(test_create_ethernet_header_2);
  CPPUNIT_TEST(test_create_ethernet_header_3);
  CPPUNIT_TEST(test_non_supported_protocol);
  CPPUNIT_TEST(test_stream_operator);
  CPPUNIT_TEST(test_mac_to_binary);
  CPPUNIT_TEST(test_binary_to_mac);
  CPPUNIT_TEST_SUITE_END();

  const std::vector<uint8_t> lcc_not_supported =
      to_binary(lcc_not_supported_ipv4_0_wireshark);
  const std::vector<uint8_t> lcc_loopback =
      to_binary(lcc_loopback_ipv4_0_wireshark);
  const std::vector<uint8_t> lcc_ipv4_0 = to_binary(lcc_ipv4_0_wireshark);
  const std::vector<uint8_t> lcc_ipv4_1 = to_binary(lcc_ipv4_1_wireshark);
  const std::vector<uint8_t> lcc_ipv4_2 = to_binary(lcc_ipv4_2_wireshark);
  const std::vector<uint8_t> lcc_ipv4_3 = to_binary(lcc_ipv4_3_wireshark);
  const std::vector<uint8_t> lcc_ipv6_0 = to_binary(lcc_ipv6_0_wireshark);
  const std::vector<uint8_t> ethernet_ipv4_0 =
      to_binary(ethernet_ipv4_0_wireshark);
  const std::vector<uint8_t> ethernet_ipv4_1 =
      to_binary(ethernet_ipv4_1_wireshark);
  const std::vector<uint8_t> ethernet_ipv6_0 =
      to_binary(ethernet_ipv6_0_wireshark);
  const std::vector<uint8_t> vlan_ipv4 = to_binary(vlan_ipv4_wireshark);
  const std::vector<uint8_t> vlan_ipv6 = to_binary(vlan_ipv6_wireshark);

public:
  void test_parse_lcc_not_supported() {
    CPPUNIT_ASSERT_THROW((void)parse_link_layer(DLT_LINUX_SLL,
                                                std::begin(lcc_not_supported),
                                                std::end(lcc_not_supported)),
                         std::runtime_error);
  }

  void test_parse_lcc_loopback() {
    auto ll = parse_link_layer(DLT_LINUX_SLL, std::begin(lcc_loopback),
                               std::end(lcc_loopback));
    test_ll(ll, Link_layer::lcc_header_size, "0:0:0:0:0:0",
            Payload_protocol::ipv4, "Linux cooked capture: src: 0:0:0:0:0:0");
  }

  void test_parse_lcc_ipv4() {
    auto ll = parse_link_layer(DLT_LINUX_SLL, std::begin(lcc_ipv4_0),
                               std::end(lcc_ipv4_0));
    test_ll(ll, Link_layer::lcc_header_size, "0:0:0:0:0:0",
            Payload_protocol::ipv4, "Linux cooked capture: src: 0:0:0:0:0:0");
  }

  void test_parse_lcc_ipv4_1() {
    auto ll = parse_link_layer(DLT_LINUX_SLL, std::begin(lcc_ipv4_1),
                               std::end(lcc_ipv4_1));
    test_ll(ll, Link_layer::lcc_header_size, "60:60:60:60:60:60",
            Payload_protocol::ipv4,
            "Linux cooked capture: src: 60:60:60:60:60:60");
  }

  void test_parse_lcc_ipv4_2() {
    CPPUNIT_ASSERT_THROW((void)parse_link_layer(DLT_LINUX_SLL,
                                                std::begin(lcc_ipv4_2),
                                                std::end(lcc_ipv4_2)),
                         std::length_error);
  }

  void test_parse_lcc_ipv4_3() {
    CPPUNIT_ASSERT_THROW((void)parse_link_layer(DLT_LINUX_SLL,
                                                std::begin(lcc_ipv4_3),
                                                std::end(lcc_ipv4_3)),
                         std::length_error);
  }

  void test_parse_lcc_ipv4_too_short() {
    CPPUNIT_ASSERT_THROW((void)parse_link_layer(DLT_LINUX_SLL,
                                                std::begin(lcc_ipv4_0),
                                                std::end(lcc_ipv4_0) - 1),
                         std::length_error);
  }

  void test_parse_lcc_ipv6() {
    auto ll = parse_link_layer(DLT_LINUX_SLL, std::begin(lcc_ipv6_0),
                               std::end(lcc_ipv6_0));
    test_ll(ll, Link_layer::lcc_header_size, "61:62:63:64:65:66",
            Payload_protocol::ipv6,
            "Linux cooked capture: src: 61:62:63:64:65:66");
  }

  void test_parse_ethernet_ipv4() {
    auto ll = parse_link_layer(DLT_EN10MB, std::begin(ethernet_ipv4_0),
                               std::end(ethernet_ipv4_0));
    test_ll(ll, Link_layer::ethernet_header_size, "0:0:0:0:0:0",
            Payload_protocol::ipv4,
            "Ethernet: dst = 0:0:0:0:0:0, src = 0:0:0:0:0:0");
  }

  void test_parse_ethernet_ipv4_1() {
    auto ll = parse_link_layer(DLT_EN10MB, std::begin(ethernet_ipv4_1),
                               std::end(ethernet_ipv4_1));
    test_ll(ll, Link_layer::ethernet_header_size, "a:b:c:d:e:f",
            Payload_protocol::ipv4,
            "Ethernet: dst = 11:2:33:4:55:6, src = a:b:c:d:e:f");
  }

  void test_parse_ethernet_ipv6() {
    auto ll = parse_link_layer(DLT_EN10MB, std::begin(ethernet_ipv6_0),
                               std::end(ethernet_ipv6_0));
    test_ll(ll, Link_layer::ethernet_header_size, "0:0:0:0:0:0",
            Payload_protocol::ipv6,
            "Ethernet: dst = 0:0:0:0:0:0, src = 0:0:0:0:0:0");
  }

  void test_parse_ethernet_ipv4_too_short() {
    CPPUNIT_ASSERT_THROW((void)parse_link_layer(DLT_EN10MB,
                                                std::begin(ethernet_ipv4_0),
                                                std::end(ethernet_ipv4_0) - 1),
                         std::length_error);
  }

  void test_parse_ethernet_ipv6_too_short() {
    CPPUNIT_ASSERT_THROW((void)parse_link_layer(DLT_EN10MB,
                                                std::begin(ethernet_ipv6_0),
                                                std::end(ethernet_ipv6_0) - 1),
                         std::length_error);
  }

  void test_parse_vlan_ipv4() {
    auto ll = parse_link_layer(ETHERTYPE_VLAN, std::begin(vlan_ipv4),
                               std::end(vlan_ipv4));
    test_ll(ll, 4, "0:0:0:0:0:0", Payload_protocol::ipv4, "VLAN Header");
  }

  void test_parse_vlan_ipv6() {
    auto ll = parse_link_layer(ETHERTYPE_VLAN, std::begin(vlan_ipv6),
                               std::end(vlan_ipv6));
    test_ll(ll, 4, "0:0:0:0:0:0", Payload_protocol::ipv6, "VLAN Header");
  }

  void test_parse_vlan_ipv4_too_short() {
    CPPUNIT_ASSERT_THROW((void)parse_link_layer(ETHERTYPE_VLAN,
                                                std::begin(vlan_ipv4),
                                                std::end(vlan_ipv4) - 1),
                         std::length_error);
  }

  void test_parse_vlan_ipv6_too_short() {
    CPPUNIT_ASSERT_THROW((void)parse_link_layer(ETHERTYPE_VLAN,
                                                std::begin(vlan_ipv6),
                                                std::end(vlan_ipv6) - 1),
                         std::length_error);
  }

  static void test_create_ethernet_header_1() {
    std::vector<uint8_t> header = create_ethernet_header(
        mac_to_binary("aa:BB:cc:dd:ee:ff"), mac_to_binary("00:11:22:33:44:55"),
        ETHERTYPE_IP);
    auto iter = std::begin(header);
    static auto const mac_start_0 = uint8_t{10};
    static auto const mac_end_0 = uint8_t{16};
    check_header(iter, std::end(header), mac_start_0, mac_end_0);
    static auto const mac_start_1 = uint8_t{0};
    static auto const mac_end_1 = uint8_t{6};
    check_header(iter, std::end(header), mac_start_1, mac_end_1);
    CPPUNIT_ASSERT((ETHERTYPE_IP >> byte_size) == *iter);
    iter++;
    CPPUNIT_ASSERT((ETHERTYPE_IP & byte_mask) == *iter);
  }

  static void test_create_ethernet_header_2() {
    std::vector<uint8_t> header = create_ethernet_header(
        mac_to_binary("66:77:88:99:aa:bb"), mac_to_binary("33:44:55:66:77:88"),
        ETHERTYPE_IPV6);
    auto iter = std::begin(header);
    static auto const mac_start_0 = uint8_t{6};
    static auto const mac_end_0 = uint8_t{12};
    check_header(iter, std::end(header), mac_start_0, mac_end_0);
    static auto const mac_start_1 = uint8_t{3};
    static auto const mac_end_1 = uint8_t{9};
    check_header(iter, std::end(header), mac_start_1, mac_end_1);
    CPPUNIT_ASSERT((ETHERTYPE_IPV6 >> byte_size) == *iter);
    iter++;
    CPPUNIT_ASSERT((ETHERTYPE_IPV6 & byte_mask) == *iter);
  }

  static void test_create_ethernet_header_3() {
    std::vector<uint8_t> header = create_ethernet_header(
        mac_to_binary("66:77:88:99:aa:bb"), mac_to_binary("33:44:55:66:77:88"),
        Link_layer::ETHERTYPE_WAKE_ON_LAN);
    auto iter = std::begin(header);
    static auto const mac_start_0 = uint8_t{6};
    static auto const mac_end_0 = uint8_t{12};
    check_header(iter, std::end(header), mac_start_0, mac_end_0);
    static auto const mac_start_1 = uint8_t{3};
    static auto const mac_end_1 = uint8_t{9};
    check_header(iter, std::end(header), mac_start_1, mac_end_1);
    CPPUNIT_ASSERT((Link_layer::ETHERTYPE_WAKE_ON_LAN >> byte_size) == *iter);
    iter++;
    CPPUNIT_ASSERT((Link_layer::ETHERTYPE_WAKE_ON_LAN & byte_mask) == *iter);
  }

  static void test_non_supported_protocol() {
    std::vector<uint8_t> data;
    static auto const max_type = uint16_t{0xFFFF};
    for (int type = 0; type < max_type; type++) {
      if (type == DLT_LINUX_SLL || type == DLT_EN10MB ||
          type == ETHERTYPE_VLAN) {
        continue;
      }
      CPPUNIT_ASSERT(std::unique_ptr<Link_layer>(nullptr) ==
                     parse_link_layer(type, std::begin(data), std::end(data)));
    }
  }

  void test_stream_operator() {
    auto const ll = parse_link_layer(DLT_EN10MB, std::begin(ethernet_ipv4_0),
                                     std::end(ethernet_ipv4_0));
    std::stringstream ss;
    ss << *ll;
    std::string const result = ss.str();
    CPPUNIT_ASSERT_EQUAL(
        std::string("Ethernet: dst = 0:0:0:0:0:0, src = 0:0:0:0:0:0"), result);
  }

  static void test_mac_to_binary() {
    std::string const mac = "00:11:Aa:Cd:65:43";
    ether_addr const binary = mac_to_binary(mac);
    std::array<uint8_t, 6> const expected_mac{
        {0x0, 0x11, 0xaa, 0xcd, 0x65, 0x43}};
    CPPUNIT_ASSERT(std::equal(std::begin(expected_mac), std::end(expected_mac),
                              std::begin(binary.ether_addr_octet)));

    std::string const mac1 = "0:11:Aa:Cd:65:43";
    ether_addr const binary1 = mac_to_binary(mac1);
    CPPUNIT_ASSERT(std::equal(std::begin(expected_mac), std::end(expected_mac),
                              std::begin(binary1.ether_addr_octet)));

    CPPUNIT_ASSERT_THROW((void)mac_to_binary("0011aacd6543"),
                         std::runtime_error);
    CPPUNIT_ASSERT_THROW((void)mac_to_binary("011AaCd6543"),
                         std::runtime_error);
    CPPUNIT_ASSERT_THROW((void)mac_to_binary("0:11::Cd:05:43"),
                         std::runtime_error);
    CPPUNIT_ASSERT_THROW((void)mac_to_binary("0:11::Cd:5:43"),
                         std::runtime_error);
    CPPUNIT_ASSERT_THROW((void)mac_to_binary("fdsafdsa"), std::runtime_error);
  }

  static void test_binary_to_mac() {
    ether_addr const binary{{0x0, 0x11, 0xaa, 0xcd, 0x65, 0x43}};
    CPPUNIT_ASSERT_EQUAL(std::string("0:11:aa:cd:65:43"),
                         binary_to_mac(binary));
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(Ethernet_test);
