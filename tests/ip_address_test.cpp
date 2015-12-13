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

#include "ip_address.h"
#include "to_string.h"

class Ip_address_test : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(Ip_address_test);
  CPPUNIT_TEST(test_parse_ip);
  CPPUNIT_TEST(test_stream_operator);
  CPPUNIT_TEST_SUITE_END();

public:
  void setUp() override {}

  void tearDown() override {}

  void compare_ip(const std::string &full_ip, const int family,
                  const std::string &ip, const uint8_t subnet) {
    const IP_address ipa = parse_ip(full_ip);
    CPPUNIT_ASSERT_EQUAL(family, ipa.family);
    CPPUNIT_ASSERT_EQUAL(ip, ipa.pure());
    CPPUNIT_ASSERT_EQUAL(static_cast<uint8_t>(subnet), ipa.subnet);
    CPPUNIT_ASSERT_EQUAL(ip + "/" + to_string(static_cast<int>(subnet)),
                         ipa.with_subnet());
  }

  void test_parse_ip() {
    compare_ip("192.168.1.1/24", AF_INET, "192.168.1.1", 24);
    compare_ip("192.168.1.1", AF_INET, "192.168.1.1", 24);
    compare_ip("192.168.1.1/16", AF_INET, "192.168.1.1", 16);
    compare_ip("fe80::12", AF_INET6, "fe80::12", 64);
    compare_ip("fe80::12%lo", AF_INET6, "fe80::12", 64);
    compare_ip("fe80::12/34%lo", AF_INET6, "fe80::12", 34);
    compare_ip("::1", AF_INET6, "::1", 128);
    compare_ip("::1/66", AF_INET6, "::1", 66);
    CPPUNIT_ASSERT_THROW(parse_ip("bla/bla/"), std::invalid_argument);
    CPPUNIT_ASSERT_THROW(parse_ip("fe80::123::123"), std::runtime_error);
    CPPUNIT_ASSERT_THROW(parse_ip("10"), std::runtime_error);
    CPPUNIT_ASSERT_THROW(parse_ip("fe80::123/200"), std::invalid_argument);
    CPPUNIT_ASSERT_THROW(parse_ip("10.0.0.1/200"), std::invalid_argument);
    CPPUNIT_ASSERT_THROW(parse_ip(""), std::invalid_argument);
  }

  void test_stream_operator() {
    std::string const ip_str = "192.168.1.2/23";
    auto const ipa = parse_ip(ip_str);
    compare_ip(ip_str, AF_INET, "192.168.1.2", 23);

    std::stringstream ss;
    ss << ipa;
    CPPUNIT_ASSERT_EQUAL(std::string("192.168.1.2/23"), ss.str());
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(Ip_address_test);
