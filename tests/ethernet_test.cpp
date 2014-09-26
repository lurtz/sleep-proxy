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
#include "check_range.h"

class Ethernet_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Ethernet_test );
        CPPUNIT_TEST( test_create_ethernet_header );
        CPPUNIT_TEST_SUITE_END();
        public:
        void setUp() {}
        void tearDown() {}

        void test_create_ethernet_header() {
                std::vector<uint8_t> header = create_ethernet_header(mac_to_binary("aa:BB:cc:dd:ee:ff"), mac_to_binary("00:11:22:33:44:55"), 0x800);
                auto iter = std::begin(header);
                check_header(iter, std::end(header), 10, 16);
                check_header(iter, std::end(header), 0, 6);
                CPPUNIT_ASSERT(0x8 == *iter);
                iter++;
                CPPUNIT_ASSERT(0x00 == *iter);

                header = create_ethernet_header(mac_to_binary("66:77:88:99:aa:bb"), mac_to_binary("33:44:55:66:77:88"), 0x86Dd);
                iter = std::begin(header);
                check_header(iter, std::end(header), 6, 12);
                check_header(iter, std::end(header), 3, 9);
                CPPUNIT_ASSERT(0x86 == *iter);
                iter++;
                CPPUNIT_ASSERT(0xdd == *iter);

                header = create_ethernet_header(mac_to_binary("66:77:88:99:aa:bb"), mac_to_binary("33:44:55:66:77:88"), 0x0842);
                iter = std::begin(header);
                check_header(iter, std::end(header), 6, 12);
                check_header(iter, std::end(header), 3, 9);
                CPPUNIT_ASSERT(0x8 == *iter);
                iter++;
                CPPUNIT_ASSERT(0x42 == *iter);
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Ethernet_test );
