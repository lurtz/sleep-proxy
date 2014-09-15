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
#include "ethernet.h"
#include "../src/ethernet.h"

class Ethernet_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Ethernet_test );
        CPPUNIT_TEST( test_create_ethernet_header );
        CPPUNIT_TEST_SUITE_END();
        public:
        void setUp() {}
        void tearDown() {}

        template<typename Iterator, typename End_iter>
        static void check_range(Iterator&& iter, End_iter&& end, const unsigned char start, const unsigned char end_pos) {
                for (unsigned char c = start; c < end_pos && iter != end; c++,iter++) {
                        CPPUNIT_ASSERT(16*c+c == *iter);
                }
                CPPUNIT_ASSERT(iter != end);
        }

        void test_create_ethernet_header() {
                std::vector<uint8_t> header = create_ethernet_header("aa:BB:cc:dd:ee:ff", "00:11:22:33:44:55", "0800");
                auto iter = std::begin(header);
                check_range(iter, std::end(header), 10, 16);
                check_range(iter, std::end(header), 0, 6);
                CPPUNIT_ASSERT(0x8 == *iter);
                iter++;
                CPPUNIT_ASSERT(0x00 == *iter);

                header = create_ethernet_header("66:77:88:99:aa:bb", "33:44:55:66:77:88", "86Dd");
                iter = std::begin(header);
                check_range(iter, std::end(header), 6, 12);
                check_range(iter, std::end(header), 3, 9);
                CPPUNIT_ASSERT(0x86 == *iter);
                iter++;
                CPPUNIT_ASSERT(0xdd == *iter);

                header = create_ethernet_header("66:77:88:99:aa:bb", "33:44:55:66:77:88", "0842");
                iter = std::begin(header);
                check_range(iter, std::end(header), 6, 12);
                check_range(iter, std::end(header), 3, 9);
                CPPUNIT_ASSERT(0x8 == *iter);
                iter++;
                CPPUNIT_ASSERT(0x42 == *iter);
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Ethernet_test );
