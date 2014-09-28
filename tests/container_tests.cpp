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

class Join_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Join_test );
        CPPUNIT_TEST( testConstructor );
        CPPUNIT_TEST_SUITE_END();
        public:
        void setUp() {}
        void tearDown() {}
        void testConstructor() {
                std::string result = join(std::vector<int>(), identity<int>, "," );
                CPPUNIT_ASSERT_EQUAL(std::string(""), result);
                std::vector<int> ints{1,2,3,4};
                result = join(ints, identity<int>, ",");
                CPPUNIT_ASSERT_EQUAL(std::string("1,2,3,4"), result);
                std::vector<std::string> strings{"a","b","c","d"};
                result = join(strings, identity<std::string>, ",");
                CPPUNIT_ASSERT_EQUAL(std::string("a,b,c,d"), result);
                std::array<uint8_t, 3> arr{{10,20,30}};
                result = join(arr, identity<int>, ";");
                CPPUNIT_ASSERT_EQUAL(std::string("10;20;30"), result);
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Join_test );

