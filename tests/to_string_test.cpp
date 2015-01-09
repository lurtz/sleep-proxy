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

#include "to_string.h"

class To_string_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( To_string_test );
        CPPUNIT_TEST( test_to_string );
        CPPUNIT_TEST( test_test_characters );
        CPPUNIT_TEST( test_get_c_string_array );
        CPPUNIT_TEST( test_get_tmp_file );
        CPPUNIT_TEST_SUITE_END();
        public:
        void setUp() {}

        void tearDown() {}

        void test_to_string() {
                CPPUNIT_ASSERT_EQUAL(std::string("1"), to_string(1));
                CPPUNIT_ASSERT_EQUAL(std::string("0.1"), to_string(0.1));
                std::string test{"blabla"};
                CPPUNIT_ASSERT_EQUAL(test, to_string(test));
                CPPUNIT_ASSERT_EQUAL(std::string(""), to_string(""));

        }

        void test_test_characters() {
                std::string valid_chars{"abcdefgh"};
                test_characters(valid_chars, valid_chars, "should not fail");
                test_characters("abc", valid_chars, "should not fail");
                test_characters("aaaaaaggggeeeebc", valid_chars, "should not fail");
                CPPUNIT_ASSERT_THROW(test_characters("i", valid_chars, "should fail"), std::runtime_error);
        }

        void compare(const std::vector<std::string>& strings, const std::vector<const char *>& c_strings) {
                auto c_strings_iter = std::begin(c_strings);
                for (const auto& string : strings) {
                        CPPUNIT_ASSERT_EQUAL(string.c_str(), *c_strings_iter);
                        c_strings_iter++;
                }
                CPPUNIT_ASSERT(nullptr == *c_strings_iter);
        }

        void test_get_c_string_array() {
                std::vector<std::string> strings;
                compare(strings, get_c_string_array(strings));
                std::vector<std::string> strings1{"bla", "foo", "bar"};
                compare(strings1, get_c_string_array(strings1));
        }

        void test_get_tmp_file() {
                File_descriptor tmp_name = get_tmp_file("blaXXXXXX");
                CPPUNIT_ASSERT(0 < tmp_name);
                CPPUNIT_ASSERT_THROW(get_tmp_file("tmp/blaXXXXXX"), std::runtime_error);
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( To_string_test );

