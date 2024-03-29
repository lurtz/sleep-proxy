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

#include "ip_address.h"

#include "to_string.h"

#include <cppunit/extensions/HelperMacros.h>

class Ip_address_test : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(Ip_address_test);
  CPPUNIT_TEST(test_parse_ip);
  CPPUNIT_TEST(test_stream_operator);
  CPPUNIT_TEST_SUITE_END();

public:
  void setUp() override {}

  void tearDown() override {}

  static void compare_ip(const std::string &full_ip, const int family,
                         const std::string &ip, const uint8_t subnet) {
    const IP_address ipa = parse_ip(full_ip);
    CPPUNIT_ASSERT_EQUAL(family, ipa.family);
    CPPUNIT_ASSERT_EQUAL(ip, ipa.pure());
    CPPUNIT_ASSERT_EQUAL(static_cast<uint8_t>(subnet), ipa.subnet);
    CPPUNIT_ASSERT_EQUAL(ip + "/" + to_string(static_cast<int>(subnet)),
                         ipa.with_subnet());
  }

  static void test_parse_ip() {
    static auto const subnet_size_24 = uint8_t{24};
    static auto const subnet_size_16 = uint8_t{16};
    static auto const subnet_size_64 = uint8_t{64};
    static auto const subnet_size_128 = uint8_t{128};
    static auto const subnet_size_34 = uint8_t{34};
    static auto const subnet_size_66 = uint8_t{66};
    compare_ip("192.168.1.1/24", AF_INET, "192.168.1.1", subnet_size_24);
    compare_ip("192.168.1.1", AF_INET, "192.168.1.1", subnet_size_24);
    compare_ip("192.168.1.1/16", AF_INET, "192.168.1.1", subnet_size_16);
    compare_ip("fe80::12", AF_INET6, "fe80::12", subnet_size_64);
    compare_ip("fe80::12%lo", AF_INET6, "fe80::12", subnet_size_64);
    compare_ip("fe80::12/34%lo", AF_INET6, "fe80::12", subnet_size_34);
    compare_ip("::1", AF_INET6, "::1", subnet_size_128);
    compare_ip("::1/66", AF_INET6, "::1", subnet_size_66);
    CPPUNIT_ASSERT_THROW((void)parse_ip("bla/bla/"), std::invalid_argument);
    CPPUNIT_ASSERT_THROW((void)parse_ip("fe80::123::123"), std::runtime_error);
    CPPUNIT_ASSERT_THROW((void)parse_ip("10"), std::runtime_error);
    CPPUNIT_ASSERT_THROW((void)parse_ip("fe80::123/200"),
                         std::invalid_argument);
    CPPUNIT_ASSERT_THROW((void)parse_ip("10.0.0.1/200"), std::invalid_argument);
    CPPUNIT_ASSERT_THROW((void)parse_ip(""), std::invalid_argument);
  }

  static void test_stream_operator() {
    static auto const subnet_size_23 = uint8_t{23};
    std::string const ip_str = "192.168.1.2/23";
    auto const ipa = parse_ip(ip_str);
    compare_ip(ip_str, AF_INET, "192.168.1.2", subnet_size_23);

    std::stringstream ss;
    ss << ipa;
    CPPUNIT_ASSERT_EQUAL(std::string("192.168.1.2/23"), ss.str());
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(Ip_address_test);
