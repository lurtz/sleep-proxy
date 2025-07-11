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

#include "to_string.h"

#include <cppunit/extensions/HelperMacros.h>
#include <string>

class To_string_test : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(To_string_test);
  CPPUNIT_TEST(test_vector_stream);
  CPPUNIT_TEST(test_to_string);
  CPPUNIT_TEST(test_test_characters);
  CPPUNIT_TEST(test_get_c_string_array);
  CPPUNIT_TEST_SUITE_END();

public:
  void setUp() override {}

  void tearDown() override {}

  static void test_vector_stream() {
    std::vector<int> vi;
    std::stringstream ss;
    ss << vi;
    CPPUNIT_ASSERT_EQUAL(std::string(""), ss.str());

    vi.push_back(3);
    ss.str("");
    ss << vi;
    CPPUNIT_ASSERT_EQUAL(std::string("3"), ss.str());

    // NOLINTNEXTLINE
    vi.push_back(8);
    ss.str("");
    ss << vi;
    CPPUNIT_ASSERT_EQUAL(std::string("3, 8"), ss.str());

    std::vector<std::string> vs{"blaa"};
    ss.str("");
    ss << vs;
    CPPUNIT_ASSERT_EQUAL(std::string("blaa"), ss.str());
  }

  static void test_to_string() {
    CPPUNIT_ASSERT_EQUAL(std::string("1"), to_string(1));
    auto const result = to_string(0.1);
    CPPUNIT_ASSERT_EQUAL(std::string("0.1"), result);
    std::string test{"blabla"};
    CPPUNIT_ASSERT_EQUAL(test, to_string(test));
    CPPUNIT_ASSERT_EQUAL(std::string(""), to_string(""));
  }

  static void test_test_characters() {
    std::string valid_chars{"abcdefgh"};
    test_characters(valid_chars, valid_chars, "should not fail");
    test_characters("abc", valid_chars, "should not fail");
    test_characters("aaaaaaggggeeeebc", valid_chars, "should not fail");
    CPPUNIT_ASSERT_THROW(test_characters("i", valid_chars, "should fail"),
                         std::runtime_error);
  }

  static void compare(const std::vector<std::string> &strings,
                      const std::vector<char *> &c_strings) {
    auto c_strings_iter = std::begin(c_strings);
    for (const auto &string : strings) {
      CPPUNIT_ASSERT_EQUAL(string, std::string{*c_strings_iter});
      c_strings_iter++;
    }
    CPPUNIT_ASSERT(nullptr == *c_strings_iter);
  }

  static void test_get_c_string_array() {
    std::vector<std::string> strings;
    auto vs = to_vector_strings(strings);
    compare(strings, get_c_string_array(vs));
    std::vector<std::string> strings1{"bla", "foo", "bar"};
    vs = to_vector_strings(strings1);
    compare(strings1, get_c_string_array(vs));
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(To_string_test);
