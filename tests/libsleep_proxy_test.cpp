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

#include "../src/libsleep_proxy.h"
#include "../src/libsleep_proxy_test_interface.h"
#include <csignal>

class Libsleep_proxy_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Libsleep_proxy_test );
        CPPUNIT_TEST( test_sigterm );
        CPPUNIT_TEST( test_sigint );
        CPPUNIT_TEST( test_ping_and_wait );
        CPPUNIT_TEST( test_duplicate_address_detection_exception );
        CPPUNIT_TEST( test_get_bindable_ip );
        CPPUNIT_TEST_SUITE_END();
        public:
        void setUp() {
                reset_signaled();
        }

        void tearDown() {}

        void test_sigterm() {
                CPPUNIT_ASSERT(!is_signaled());
                setup_signals();
                CPPUNIT_ASSERT(!is_signaled());
                raise(SIGTERM);
                CPPUNIT_ASSERT(is_signaled());
        }

        void test_sigint() {
                CPPUNIT_ASSERT(!is_signaled());
                setup_signals();
                CPPUNIT_ASSERT(!is_signaled());
                raise(SIGINT);
                CPPUNIT_ASSERT(is_signaled());
        }

        void test_ping_and_wait() {
                CPPUNIT_ASSERT(ping_and_wait("lo", "127.0.0.1", 1));
                CPPUNIT_ASSERT(!ping_and_wait("lo", "127.0.0.1", 0));
                CPPUNIT_ASSERT(ping_and_wait("eth0", "127.0.0.1", 1));
                CPPUNIT_ASSERT(!ping_and_wait("eth0", "127.0.0.1", 0));
                CPPUNIT_ASSERT(ping_and_wait("lo", "::1", 1));
                CPPUNIT_ASSERT(!ping_and_wait("lo", "::1", 0));
                CPPUNIT_ASSERT(ping_and_wait("eth0", "::1", 1));
                CPPUNIT_ASSERT(!ping_and_wait("eth0", "::1", 0));

                CPPUNIT_ASSERT(!ping_and_wait("lo", "192.168.254.200", 1));
                CPPUNIT_ASSERT(!ping_and_wait("eth0", "192.168.254.200", 1));
                CPPUNIT_ASSERT(!ping_and_wait("lo", "::2", 1));
                CPPUNIT_ASSERT(!ping_and_wait("eth0", "::2", 1));
        }

        void test_duplicate_address_detection_exception() {
                bool catched = false;
                const std::string txt = "here would is txt";
                try {
                        throw Duplicate_address_exception(txt);
                }
                catch (const Duplicate_address_exception& e) {
                        catched = true;
                        CPPUNIT_ASSERT_EQUAL("one of these ips is owned by another machine: " + txt, std::string(e.what()));
                }
                CPPUNIT_ASSERT(catched);
        }

        void test_get_bindable_ip() {
                const std::string ipv4 = "somestuff";
                const std::string ipv6 = "fe80::123";
                CPPUNIT_ASSERT_EQUAL(ipv4, get_bindable_ip("lo", ipv4));
                CPPUNIT_ASSERT_EQUAL(ipv6 + "%lo", get_bindable_ip("lo", ipv6));
                CPPUNIT_ASSERT_EQUAL(ipv4, get_bindable_ip("bla", ipv4));
                CPPUNIT_ASSERT_EQUAL(ipv6 + "%bla", get_bindable_ip("bla", ipv6));
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Libsleep_proxy_test );

