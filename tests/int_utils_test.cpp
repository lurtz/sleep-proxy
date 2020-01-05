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

#include "int_utils.h"

#include <string>
#include <cppunit/extensions/HelperMacros.h>

class Str_to_integral_test : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(Str_to_integral_test);
  CPPUNIT_TEST(testConstructor);
  CPPUNIT_TEST_EXCEPTION(outofnegbounds, std::out_of_range);
  CPPUNIT_TEST_EXCEPTION(outofposbounds, std::out_of_range);
  CPPUNIT_TEST(test_stoll);
  CPPUNIT_TEST(test_stoull);
  CPPUNIT_TEST(test_uint32_t_to_eight_hex_chars);
  CPPUNIT_TEST_SUITE_END();

public:
  void setUp() override {}
  void tearDown() override {}
  void testConstructor() {
    CPPUNIT_ASSERT_EQUAL(0, str_to_integral<int>("0"));
    CPPUNIT_ASSERT_EQUAL(1, str_to_integral<int>("1"));
    CPPUNIT_ASSERT_EQUAL(-1, str_to_integral<int>("-1"));
    CPPUNIT_ASSERT_EQUAL(static_cast<unsigned int>(9001),
                         str_to_integral<unsigned int>("9001"));
  }

  void outofnegbounds() { str_to_integral<unsigned int>("-1"); }

  void outofposbounds() { str_to_integral<uint8_t>("256"); }

  void test_stoll() {
    CPPUNIT_ASSERT_EQUAL(static_cast<int64_t>(123),
                         stoll_with_checks("123"));
    CPPUNIT_ASSERT_EQUAL(static_cast<int64_t>(-123),
                         stoll_with_checks("-123"));
    CPPUNIT_ASSERT_EQUAL(static_cast<int64_t>(0), stoll_with_checks("0"));
    CPPUNIT_ASSERT_THROW(stoll_with_checks("1234567890123456789123456789"),
                         std::out_of_range);
    CPPUNIT_ASSERT_THROW(stoll_with_checks("-1234567890123456789123456789"),
                         std::out_of_range);
    CPPUNIT_ASSERT_THROW(stoll_with_checks("fdasfd"), std::invalid_argument);

    CPPUNIT_ASSERT_EQUAL(static_cast<int64_t>(0),
                         stoll_with_checks("0", 16));
    CPPUNIT_ASSERT_EQUAL(static_cast<int64_t>(10),
                         stoll_with_checks("a", 16));
    CPPUNIT_ASSERT_EQUAL(static_cast<int64_t>(15),
                         stoll_with_checks("F", 16));
  }

  void test_stoull() {
    CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(123),
                         stoull_with_checks("123"));
    CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(0), stoull_with_checks("0"));
    CPPUNIT_ASSERT_THROW(stoull_with_checks("-123"), std::out_of_range);
    CPPUNIT_ASSERT_THROW(stoull_with_checks("12345678901234567890123456789"),
                         std::out_of_range);
    CPPUNIT_ASSERT_THROW(stoull_with_checks("fdasfd"),
                         std::invalid_argument);

    CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(0),
                         stoull_with_checks("0", 16));
    CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(10),
                         stoull_with_checks("a", 16));
    CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(15),
                         stoull_with_checks("F", 16));
  }

  void test_uint32_t_to_eight_hex_chars() {
    CPPUNIT_ASSERT_EQUAL(std::string("00000000"),
                         uint32_t_to_eight_hex_chars(0));

    CPPUNIT_ASSERT_EQUAL(std::string("0000000a"),
                         uint32_t_to_eight_hex_chars(10 << 24));
    CPPUNIT_ASSERT_EQUAL(
        std::string("000000a0"),
        uint32_t_to_eight_hex_chars(static_cast<uint32_t>(160) << 24));
    CPPUNIT_ASSERT_EQUAL(
        std::string("000000ff"),
        uint32_t_to_eight_hex_chars(static_cast<uint32_t>(255) << 24));

    CPPUNIT_ASSERT_EQUAL(std::string("00000a00"),
                         uint32_t_to_eight_hex_chars(10 << 16));
    CPPUNIT_ASSERT_EQUAL(std::string("0000a000"),
                         uint32_t_to_eight_hex_chars(160 << 16));
    CPPUNIT_ASSERT_EQUAL(std::string("0000ff00"),
                         uint32_t_to_eight_hex_chars(255 << 16));

    CPPUNIT_ASSERT_EQUAL(std::string("000a0000"),
                         uint32_t_to_eight_hex_chars(10 << 8));
    CPPUNIT_ASSERT_EQUAL(std::string("00a00000"),
                         uint32_t_to_eight_hex_chars(160 << 8));
    CPPUNIT_ASSERT_EQUAL(std::string("00ff0000"),
                         uint32_t_to_eight_hex_chars(255 << 8));

    CPPUNIT_ASSERT_EQUAL(std::string("0a000000"),
                         uint32_t_to_eight_hex_chars(10));
    CPPUNIT_ASSERT_EQUAL(std::string("a0000000"),
                         uint32_t_to_eight_hex_chars(160));
    CPPUNIT_ASSERT_EQUAL(std::string("ff000000"),
                         uint32_t_to_eight_hex_chars(255));
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(Str_to_integral_test);
