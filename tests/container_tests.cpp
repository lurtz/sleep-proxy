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
#include "main.h"
#include <string>

#include "container_utils.h"

class Join_test : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(Join_test);
  CPPUNIT_TEST(testConstructor);
  CPPUNIT_TEST(test_vector_addition);
  CPPUNIT_TEST(test_split);
  CPPUNIT_TEST(test_split_string);
  CPPUNIT_TEST_SUITE_END();

public:
  void setUp() {}
  void tearDown() {}
  void testConstructor() {
    std::string result = join(std::vector<int>(), identity<int>, ",");
    CPPUNIT_ASSERT_EQUAL(std::string(""), result);
    std::vector<int> ints{1, 2, 3, 4};
    result = join(ints, identity<int>, ",");
    CPPUNIT_ASSERT_EQUAL(std::string("1,2,3,4"), result);
    std::vector<std::string> strings{"a", "b", "c", "d"};
    result = join(strings, identity<std::string>, ",");
    CPPUNIT_ASSERT_EQUAL(std::string("a,b,c,d"), result);
    std::array<uint8_t, 3> arr{{10, 20, 30}};
    result = join(arr, identity<int>, ";");
    CPPUNIT_ASSERT_EQUAL(std::string("10;20;30"), result);
  }

  void test_vector_addition() {
    std::vector<int> v0{1, 2, 3};
    std::vector<int> v1{4, 5, 6};
    std::vector<int> r0{1, 2, 3, 4, 5, 6};
    CPPUNIT_ASSERT(r0 == std::move(v0) + v1);
    CPPUNIT_ASSERT(std::vector<int>() ==
                   std::vector<int>() + std::vector<int>());
  }

  void test_split() {
    std::vector<std::vector<std::string>> const empty_result =
        split(std::vector<std::string>(), "");
    CPPUNIT_ASSERT_EQUAL(static_cast<unsigned long>(0), empty_result.size());

    std::vector<int> const v0{1, 2, 3, 0, 1, 2, 3, 4, 0, 5, 6, 7, 8};
    std::vector<std::vector<int>> const result = split(v0, 0);

    CPPUNIT_ASSERT_EQUAL(static_cast<unsigned long>(3), result.size());
    CPPUNIT_ASSERT_EQUAL((std::vector<int>{1, 2, 3}), result.at(0));
    CPPUNIT_ASSERT_EQUAL((std::vector<int>{1, 2, 3, 4}), result.at(1));
    CPPUNIT_ASSERT_EQUAL((std::vector<int>{5, 6, 7, 8}), result.at(2));
  }

  void test_split_string() {
    std::vector<std::string> result0{"a", "b", "c"};
    CPPUNIT_ASSERT(result0 == split(std::string("a,b,c"), ','));
    std::vector<std::string> result1{"a,b,c"};
    CPPUNIT_ASSERT(result1 == split(std::string("a,b,c"), ';'));
    std::vector<std::string> result2{};
    CPPUNIT_ASSERT(result2 == split(std::string(""), ';'));
    std::vector<std::string> result3{"a", "b", "c", "d"};
    CPPUNIT_ASSERT(result3 == split(std::string("a;b;c;d"), ';'));
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(Join_test);
