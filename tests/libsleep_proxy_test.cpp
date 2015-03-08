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

#include "libsleep_proxy.h"
#include "libsleep_proxy_test_interface.h"
#include "container_utils.h"
#include "ip_utils.h"
#include <csignal>

class Libsleep_proxy_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Libsleep_proxy_test );
        CPPUNIT_TEST( test_sigterm );
        CPPUNIT_TEST( test_sigint );
        CPPUNIT_TEST( test_ping_and_wait );
        CPPUNIT_TEST( test_duplicate_address_detection_exception );
        CPPUNIT_TEST( test_get_bindable_ip );
        CPPUNIT_TEST( test_rule_to_listen_on_ips_and_ports );
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
                CPPUNIT_ASSERT(ping_and_wait("lo", parse_ip("127.0.0.1"), 1));
                CPPUNIT_ASSERT(!ping_and_wait("lo", parse_ip("127.0.0.1"), 0));
                CPPUNIT_ASSERT(ping_and_wait("eth0", parse_ip("127.0.0.1"), 1));
                CPPUNIT_ASSERT(!ping_and_wait("eth0", parse_ip("127.0.0.1"), 0));
                CPPUNIT_ASSERT(ping_and_wait("lo", parse_ip("::1"), 1));
                CPPUNIT_ASSERT(!ping_and_wait("lo", parse_ip("::1"), 0));
                CPPUNIT_ASSERT(ping_and_wait("eth0", parse_ip("::1"), 1));
                CPPUNIT_ASSERT(!ping_and_wait("eth0", parse_ip("::1"), 0));

                CPPUNIT_ASSERT(!ping_and_wait("lo", parse_ip("192.168.254.200"), 1));
                CPPUNIT_ASSERT(!ping_and_wait("eth0", parse_ip("192.168.254.200"), 1));
                CPPUNIT_ASSERT(!ping_and_wait("lo", parse_ip("::2"), 1));
                CPPUNIT_ASSERT(!ping_and_wait("eth0", parse_ip("::2"), 1));
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

        std::vector<IP_address> parse_ips(const std::string& ips) {
                return parse_items(split(ips, ','), parse_ip);
        }

        void test_rule_to_listen_on_ips_and_ports() {
                std::vector<IP_address> ips = parse_ips("192.168.1.1");
                std::vector<uint16_t> ports{22};
                std::string expected_rule = "tcp[tcpflags] == tcp-syn";
                expected_rule += " and dst host (192.168.1.1)";
                expected_rule += " and dst port (22)";
                CPPUNIT_ASSERT_EQUAL(expected_rule, rule_to_listen_on_ips_and_ports(ips, ports));

                ips.push_back(parse_ip("192.168.23.23/16"));
                expected_rule = "tcp[tcpflags] == tcp-syn";
                expected_rule += " and dst host (192.168.1.1 or 192.168.23.23)";
                expected_rule += " and dst port (22)";
                CPPUNIT_ASSERT_EQUAL(expected_rule, rule_to_listen_on_ips_and_ports(ips, ports));

                ports.push_back(123);
                expected_rule = "tcp[tcpflags] == tcp-syn";
                expected_rule += " and dst host (192.168.1.1 or 192.168.23.23)";
                expected_rule += " and dst port (22 or 123)";
                CPPUNIT_ASSERT_EQUAL(expected_rule, rule_to_listen_on_ips_and_ports(ips, ports));
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Libsleep_proxy_test );

