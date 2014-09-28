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

#include "scope_guard.h"

class Duplicate_address_watcher_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Duplicate_address_watcher_test );
        CPPUNIT_TEST( test_duplicate_address_watcher );
        CPPUNIT_TEST_SUITE_END();
        public:
        void setUp() {}

        void tearDown() {}

        struct Pcap_dummy : public Pcap_wrapper {
                Pcap_dummy() {}
                Pcap_wrapper::Loop_end_reason get_end_reason() const {
                        return loop_end_reason;
                }
        };

        void test_duplicate_address_watcher() {
                Pcap_dummy pcap;
                Duplicate_address_watcher daw{"eth0", parse_ip("10.0.0.1/16"), pcap};
                CPPUNIT_ASSERT_EQUAL(std::string(""), daw(Action::add));
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                CPPUNIT_ASSERT(Pcap_dummy().get_end_reason() == pcap.get_end_reason());
                CPPUNIT_ASSERT_EQUAL(std::string(""), daw(Action::del));
                CPPUNIT_ASSERT(Pcap_dummy().get_end_reason() == pcap.get_end_reason());
                Duplicate_address_watcher daw2{"wlan0", parse_ip("192.168.1.1/24"), pcap};
                Duplicate_address_watcher daw3{"eth0", parse_ip("192.168.1.1/24"), pcap};
                CPPUNIT_ASSERT_EQUAL(std::string(""), daw2(Action::add));
                CPPUNIT_ASSERT_EQUAL(std::string(""), daw3(Action::add));
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                CPPUNIT_ASSERT_EQUAL(std::string(""), daw2(Action::del));
                CPPUNIT_ASSERT_EQUAL(std::string(""), daw3(Action::del));
                CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::duplicate_address == pcap.get_end_reason());
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Duplicate_address_watcher_test );

