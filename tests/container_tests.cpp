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

#include "../src/container_utils.h"

class Join_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Join_test );
        CPPUNIT_TEST( testConstructor );
        CPPUNIT_TEST_SUITE_END();
        public:
        void setUp() {}
        void tearDown() {}
        void testConstructor() {
                auto lambid = [](const int i){return i;};
                std::string result = join(std::vector<int>(), lambid, "," );
                CPPUNIT_ASSERT_EQUAL(std::string(""), result);
                std::vector<int> ints{1,2,3,4};
                result = join(ints, lambid, ",");
                CPPUNIT_ASSERT_EQUAL(std::string("1,2,3,4"), result);
                std::vector<std::string> strings{"a","b","c","d"};
                result = join(strings, [](const std::string& s){return s;}, ",");
                CPPUNIT_ASSERT_EQUAL(std::string("a,b,c,d"), result);
                std::array<uint8_t, 3> arr{{10,20,30}};
                result = join(arr, lambid, ";");
                CPPUNIT_ASSERT_EQUAL(std::string("10;20;30"), result);
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Join_test );

class Repeat_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Repeat_test );
        CPPUNIT_TEST( testConstructor );
        CPPUNIT_TEST_SUITE_END();
        public:
        void setUp() {}
        void tearDown() {}
        void testConstructor() {
                CPPUNIT_ASSERT_EQUAL(0, repeat(10, 0, 0));
                CPPUNIT_ASSERT_EQUAL(10, repeat(10, 1, 0));
                CPPUNIT_ASSERT_EQUAL(20, repeat(10, 2, 0));
                CPPUNIT_ASSERT_EQUAL(std::string(""), repeat(std::string("asdf"), 0, std::string("")));
                CPPUNIT_ASSERT_EQUAL(std::string("asdf"), repeat(std::string("asdf"), 1, std::string("")));
                CPPUNIT_ASSERT_EQUAL(std::string("asdfasdf"), repeat(std::string("asdf"), 2, std::string("")));
                CPPUNIT_ASSERT_EQUAL(std::string("blaasdfasdf"), repeat(std::string("asdf"), 2, std::string("bla")));
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Repeat_test );

