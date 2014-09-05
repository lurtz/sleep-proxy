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

#include "split.h"

class Split_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Split_test );
        CPPUNIT_TEST( testConstructor );
        CPPUNIT_TEST_SUITE_END();
        public:
        void setUp() {}
        void tearDown() {}
        void testConstructor() {
                std::vector<std::string> result0{"a","b","c"};
                CPPUNIT_ASSERT(result0 == split("a,b,c", ','));
                std::vector<std::string> result1{"a,b,c"};
                CPPUNIT_ASSERT(result1 == split("a,b,c", ';'));
                std::vector<std::string> result2{};
                CPPUNIT_ASSERT(result2 == split("", ';'));
                std::vector<std::string> result3{"a","b","c","d"};
                CPPUNIT_ASSERT(result3 == split("a;b;c;d", ';'));
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Split_test );

