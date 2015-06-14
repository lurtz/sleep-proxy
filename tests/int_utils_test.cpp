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

#include "int_utils.h"

class Str_to_integral_test : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(Str_to_integral_test);
  CPPUNIT_TEST(testConstructor);
  CPPUNIT_TEST_EXCEPTION(outofnegbounds, std::out_of_range);
  CPPUNIT_TEST_EXCEPTION(outofposbounds, std::out_of_range);
  CPPUNIT_TEST(test_stoll);
  CPPUNIT_TEST(test_stoull);
  CPPUNIT_TEST(test_one_byte_to_two_hex_chars);
  CPPUNIT_TEST_SUITE_END();

public:
  void setUp() {}
  void tearDown() {}
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
    CPPUNIT_ASSERT_EQUAL(static_cast<long long int>(123),
                         fallback::std::stoll("123"));
    CPPUNIT_ASSERT_EQUAL(static_cast<long long int>(-123),
                         fallback::std::stoll("-123"));
    CPPUNIT_ASSERT_EQUAL(static_cast<long long int>(0),
                         fallback::std::stoll("0"));
    CPPUNIT_ASSERT_THROW(fallback::std::stoll("1234567890123456789123456789"),
                         std::out_of_range);
    CPPUNIT_ASSERT_THROW(fallback::std::stoll("-1234567890123456789123456789"),
                         std::out_of_range);
    CPPUNIT_ASSERT_THROW(fallback::std::stoll("fdasfd"), std::invalid_argument);

    CPPUNIT_ASSERT_EQUAL(static_cast<long long int>(0),
                         fallback::std::stoll("0", 16));
    CPPUNIT_ASSERT_EQUAL(static_cast<long long int>(10),
                         fallback::std::stoll("a", 16));
    CPPUNIT_ASSERT_EQUAL(static_cast<long long int>(15),
                         fallback::std::stoll("F", 16));
  }

  void test_stoull() {
    CPPUNIT_ASSERT_EQUAL(static_cast<unsigned long long int>(123),
                         fallback::std::stoull("123"));
    CPPUNIT_ASSERT_EQUAL(static_cast<unsigned long long int>(0),
                         fallback::std::stoull("0"));
    CPPUNIT_ASSERT_THROW(fallback::std::stoull("-123"), std::out_of_range);
    CPPUNIT_ASSERT_THROW(fallback::std::stoull("12345678901234567890123456789"),
                         std::out_of_range);
    CPPUNIT_ASSERT_THROW(fallback::std::stoull("fdasfd"),
                         std::invalid_argument);

    CPPUNIT_ASSERT_EQUAL(static_cast<unsigned long long int>(0),
                         fallback::std::stoull("0", 16));
    CPPUNIT_ASSERT_EQUAL(static_cast<unsigned long long int>(10),
                         fallback::std::stoull("a", 16));
    CPPUNIT_ASSERT_EQUAL(static_cast<unsigned long long int>(15),
                         fallback::std::stoull("F", 16));
  }

  void test_one_byte_to_two_hex_chars() {
    CPPUNIT_ASSERT_EQUAL(std::string("ff"), one_byte_to_two_hex_chars(255));
    CPPUNIT_ASSERT_EQUAL(std::string("00"), one_byte_to_two_hex_chars(0));
    CPPUNIT_ASSERT_EQUAL(std::string("0a"), one_byte_to_two_hex_chars(10));
    CPPUNIT_ASSERT_EQUAL(std::string("a0"), one_byte_to_two_hex_chars(160));
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(Str_to_integral_test);
