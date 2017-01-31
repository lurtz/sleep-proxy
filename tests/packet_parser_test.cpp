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

#include "container_utils.h"
#include "ethernet.h"
#include "int_utils.h"
#include "packet_parser.h"

#include "packet_test_utils.h"

const std::string ethernet_ipv4_tcp_wireshark =
    "00000000000000000000000008004500003c88d040004006b3e97f0000017f000001";

const std::string ethernet_ipv6_tcp_wireshark =
    "00000000000000000000000086dd6000000000280640000000000000000000000000000000"
    "0100000000000000000000000000000001";

const std::string lcc_unknown_udp_wireshark =
    "000001010006000000000000000008004500003e057f40004011372e7f0000017f000001";

const std::string lcc_ipv4_udp_wireshark =
    "000000010006000000000000000008004500003e057f40004011372e7f0000017f000001";

const std::string lcc_ipv6_tcp_wireshark =
    "000000010006000000000000000086dd600000000014064000000000000000000000000000"
    "00000100000000000000000000000000000001";

// src 192.168.1.155 dst 79.143.179.211 UDP 164
const std::string lcc_vlan_ipv4_udp_wireshark = "000000010006e8de2755a171000081"
                                                "000001080045000090000040004011"
                                                "74b7c0a8019b4f8fb3d3";

class Packet_parser_test : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(Packet_parser_test);
  CPPUNIT_TEST(test_parse_ethernet_ipv4_tcp);
  CPPUNIT_TEST(test_parse_ethernet_ipv6_tcp);
  CPPUNIT_TEST(test_parse_ethernet_ipv4_tcp_too_short);
  CPPUNIT_TEST(test_parse_ethernet_ipv6_tcp_too_short);
  CPPUNIT_TEST(test_parse_lcc_ipv4_udp);
  CPPUNIT_TEST(test_parse_lcc_ipv6_tcp);
  CPPUNIT_TEST(test_parse_lcc_ipv4_udp_too_short);
  CPPUNIT_TEST(test_parse_lcc_ipv6_tcp_too_short);
  CPPUNIT_TEST(test_parse_lcc_vlan_ipv4_udp);
  CPPUNIT_TEST(test_parse_lcc_vlan_ipv4_udp_too_short);
  CPPUNIT_TEST(test_parse_unknown_link_layer);
  CPPUNIT_TEST(test_parse_unknown_ip);
  CPPUNIT_TEST(test_catch_incoming_connection);
  CPPUNIT_TEST(test_catch_incoming_connection_unknown_lcc_protocol);
  CPPUNIT_TEST(test_catch_incoming_connection_void_ptr);
  CPPUNIT_TEST(test_stream_operator);
  CPPUNIT_TEST_SUITE_END();

  const std::vector<uint8_t> ethernet_ipv4_tcp =
      to_binary(ethernet_ipv4_tcp_wireshark);
  const std::vector<uint8_t> ethernet_ipv6_tcp =
      to_binary(ethernet_ipv6_tcp_wireshark);
  const std::vector<uint8_t> lcc_unknown_udp =
      to_binary(lcc_unknown_udp_wireshark);
  const std::vector<uint8_t> lcc_ipv4_udp = to_binary(lcc_ipv4_udp_wireshark);
  const std::vector<uint8_t> lcc_ipv6_tcp = to_binary(lcc_ipv6_tcp_wireshark);
  const std::vector<uint8_t> lcc_vlan_ipv4_udp =
      to_binary(lcc_vlan_ipv4_udp_wireshark);

public:
  void test_parse_ethernet_ipv4_tcp() {
    auto headers = get_headers(DLT_EN10MB, ethernet_ipv4_tcp);

    auto &ll = std::get<0>(headers);
    test_ll(ll, 14, "0:0:0:0:0:0", ip::ipv4,
            "Ethernet: dst = 0:0:0:0:0:0, src = 0:0:0:0:0:0");

    test_ip(std::get<1>(headers), ip::ipv4, "127.0.0.1/32", "127.0.0.1/32", 20,
            ip::TCP);
  }

  void test_parse_ethernet_ipv6_tcp() {
    auto headers = get_headers(DLT_EN10MB, ethernet_ipv6_tcp);

    auto &ll = std::get<0>(headers);
    test_ll(ll, 14, "0:0:0:0:0:0", ip::ipv6,
            "Ethernet: dst = 0:0:0:0:0:0, src = 0:0:0:0:0:0");

    test_ip(std::get<1>(headers), ip::ipv6, "::1/128", "::1/128", 40, ip::TCP);
  }

  void test_parse_ethernet_ipv4_tcp_too_short() {
    std::vector<uint8_t> ethernet_ipv4_tcp_short(
        std::begin(ethernet_ipv4_tcp), std::end(ethernet_ipv4_tcp) - 1);
    CPPUNIT_ASSERT_THROW(get_headers(DLT_EN10MB, ethernet_ipv4_tcp_short),
                         std::length_error);
  }

  void test_parse_ethernet_ipv6_tcp_too_short() {
    std::vector<uint8_t> ethernet_ipv6_tcp_short(
        std::begin(ethernet_ipv6_tcp), std::end(ethernet_ipv6_tcp) - 1);
    CPPUNIT_ASSERT_THROW(get_headers(DLT_EN10MB, ethernet_ipv6_tcp_short),
                         std::length_error);
  }

  void test_parse_lcc_ipv4_udp() {
    auto headers = get_headers(DLT_LINUX_SLL, lcc_ipv4_udp);
    auto &ll = std::get<0>(headers);
    test_ll(ll, 16, "0:0:0:0:0:0", ip::ipv4,
            "Linux cooked capture: src: 0:0:0:0:0:0");
    test_ip(std::get<1>(headers), ip::ipv4, "127.0.0.1/32", "127.0.0.1/32", 20,
            ip::UDP);
  }

  void test_parse_lcc_ipv6_tcp() {
    auto headers = get_headers(DLT_LINUX_SLL, lcc_ipv6_tcp);
    auto &ll = std::get<0>(headers);
    test_ll(ll, 16, "0:0:0:0:0:0", ip::ipv6,
            "Linux cooked capture: src: 0:0:0:0:0:0");
    test_ip(std::get<1>(headers), ip::ipv6, "::1/128", "::1/128", 40, ip::TCP);
  }

  void test_parse_lcc_ipv4_udp_too_short() {
    std::vector<uint8_t> lcc_ipv4_udp_short(std::begin(lcc_ipv4_udp),
                                            std::end(lcc_ipv4_udp) - 1);
    CPPUNIT_ASSERT_THROW(get_headers(DLT_LINUX_SLL, lcc_ipv4_udp_short),
                         std::length_error);
  }

  void test_parse_lcc_ipv6_tcp_too_short() {
    std::vector<uint8_t> lcc_ipv6_tcp_short(std::begin(lcc_ipv6_tcp),
                                            std::end(lcc_ipv6_tcp) - 1);
    CPPUNIT_ASSERT_THROW(get_headers(DLT_LINUX_SLL, lcc_ipv6_tcp_short),
                         std::length_error);
  }

  void test_parse_lcc_vlan_ipv4_udp() {
    auto headers = get_headers(DLT_LINUX_SLL, lcc_vlan_ipv4_udp);
    auto &ll = std::get<0>(headers);
    test_ll(ll, 16, "e8:de:27:55:a1:71",
            static_cast<ip::Version>(ETHERTYPE_VLAN),
            "Linux cooked capture: src: e8:de:27:55:a1:71");
    test_ip(std::get<1>(headers), ip::ipv4, "192.168.1.155/32",
            "79.143.179.211/32", 20, ip::UDP);
  }

  void test_parse_lcc_vlan_ipv4_udp_too_short() {
    std::vector<uint8_t> lcc_vlan_ipv4_udp_short(
        std::begin(lcc_vlan_ipv4_udp), std::end(lcc_vlan_ipv4_udp) - 1);
    CPPUNIT_ASSERT_THROW(get_headers(DLT_LINUX_SLL, lcc_vlan_ipv4_udp_short),
                         std::length_error);
  }

  void test_parse_unknown_link_layer() {
    std::vector<uint8_t> const data;
    auto const headers = get_headers(-1, data);
    CPPUNIT_ASSERT(nullptr == std::get<0>(headers));
    CPPUNIT_ASSERT(nullptr == std::get<1>(headers));
  }

  void test_parse_unknown_ip() {
    std::vector<uint8_t> data{std::begin(ethernet_ipv4_tcp),
                              std::end(ethernet_ipv4_tcp)};
    data.at(12) = 0xFF;
    data.at(13) = 0xFF;
    auto const headers = get_headers(DLT_EN10MB, data);
    CPPUNIT_ASSERT(nullptr != std::get<0>(headers));
    CPPUNIT_ASSERT(nullptr == std::get<1>(headers));

    auto &ll = std::get<0>(headers);
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(14), ll->header_length());
    CPPUNIT_ASSERT_EQUAL(std::string("0:0:0:0:0:0"),
                         binary_to_mac(ll->source()));
    CPPUNIT_ASSERT_EQUAL(static_cast<uint16_t>(0xFFFF), ll->payload_protocol());
    CPPUNIT_ASSERT_EQUAL(
        std::string("Ethernet: dst = 0:0:0:0:0:0, src = 0:0:0:0:0:0"),
        ll->get_info());
  }

  void test_catch_incoming_connection() {
    auto headers = get_headers(DLT_EN10MB, ethernet_ipv4_tcp);
    Catch_incoming_connection cic(DLT_EN10MB);
    pcap_pkthdr hdr;
    hdr.len = static_cast<bpf_u_int32>(ethernet_ipv4_tcp.size());
    cic(&hdr, ethernet_ipv4_tcp.data());
    CPPUNIT_ASSERT(ethernet_ipv4_tcp == cic.data);
    CPPUNIT_ASSERT_EQUAL(*std::get<0>(headers), *std::get<0>(cic.headers));
    CPPUNIT_ASSERT_EQUAL(*std::get<1>(headers), *std::get<1>(cic.headers));
  }

  void test_catch_incoming_connection_unknown_lcc_protocol() {
    Catch_incoming_connection cic(DLT_LINUX_SLL);
    pcap_pkthdr hdr;
    hdr.len = static_cast<bpf_u_int32>(lcc_unknown_udp.size());
    cic(&hdr, lcc_unknown_udp.data());
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), cic.data.size());
    CPPUNIT_ASSERT_EQUAL(basic_headers(), cic.headers);
  }

  void test_catch_incoming_connection_void_ptr() {
    Catch_incoming_connection cic(DLT_LINUX_SLL);
    pcap_pkthdr hdr;
    hdr.len = static_cast<bpf_u_int32>(lcc_unknown_udp.size());
    cic(nullptr, nullptr);
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), cic.data.size());
    CPPUNIT_ASSERT_EQUAL(basic_headers(), cic.headers);
    cic(nullptr, lcc_unknown_udp.data());
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), cic.data.size());
    CPPUNIT_ASSERT_EQUAL(basic_headers(), cic.headers);
    cic(&hdr, nullptr);
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), cic.data.size());
    CPPUNIT_ASSERT_EQUAL(basic_headers(), cic.headers);
  }

  void test_stream_operator() {
    auto headers = get_headers(DLT_EN10MB, ethernet_ipv4_tcp);
    std::stringstream ss;
    ss << headers;
    CPPUNIT_ASSERT_EQUAL(
        std::string("Ethernet: dst = 0:0:0:0:0:0, src = 0:0:0:0:0:0\nIPv4: dst "
                    "= 127.0.0.1, src = 127.0.0.1"),
        ss.str());

    basic_headers const headers1 = std::make_tuple(
        std::unique_ptr<Link_layer>(), std::move(std::get<1>(headers)));
    ss.str("");
    ss << headers1;
    CPPUNIT_ASSERT_EQUAL(
        std::string("\nIPv4: dst = 127.0.0.1, src = 127.0.0.1"), ss.str());

    basic_headers const headers2 =
        std::make_tuple(std::move(std::get<0>(headers)), std::unique_ptr<ip>());
    ss.str("");
    ss << headers2;
    CPPUNIT_ASSERT_EQUAL(
        std::string("Ethernet: dst = 0:0:0:0:0:0, src = 0:0:0:0:0:0\n"),
        ss.str());

    basic_headers const headers3 =
        std::make_tuple(std::unique_ptr<Link_layer>(), std::unique_ptr<ip>());
    ss.str("");
    ss << headers3;
    CPPUNIT_ASSERT_EQUAL(std::string("\n"), ss.str());
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(Packet_parser_test);
