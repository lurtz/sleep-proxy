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

#include "duplicate_address_watcher.h"
#include <atomic>
#include "file_descriptor.h"
#include "to_string.h"
#include <future>

bool has_neighbour_ip(std::string const & iface, IP_address const & ip, File_descriptor const & ip_neigh_output);
void daw_thread_main_ipv6_non_root(const std::string & iface, const IP_address & ip, std::atomic_bool & loop, Pcap_wrapper & pc);

class Duplicate_address_watcher_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Duplicate_address_watcher_test );
        CPPUNIT_TEST( test_duplicate_address_watcher_ipv4 );
        CPPUNIT_TEST( test_duplicate_address_watcher_ipv6 );
        CPPUNIT_TEST( test_has_neighbour_ip );
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

        void test_duplicate_address_watcher_ipv4() {
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

        static void timeout(std::atomic_bool & loop, size_t const milliseconds) {
                std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
                loop = false;
        }

        void test_duplicate_address_watcher_ipv6() {
                Pcap_dummy pcap;
                std::atomic_bool loop{true};

                // detect ip which is propably occupied by router
                daw_thread_main_ipv6_non_root("wlan0", parse_ip("192.168.1.1/24"), loop, pcap);

                CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::duplicate_address == pcap.get_end_reason());
                CPPUNIT_ASSERT(!loop);

                // just timeout
                auto f = std::async(std::launch::async, timeout, std::ref(loop), 1000);
                pcap = Pcap_dummy();
                loop = true;

                daw_thread_main_ipv6_non_root("eth0", parse_ip("192.168.3.1/24"), loop, pcap);

                CPPUNIT_ASSERT(Pcap_dummy().get_end_reason() == pcap.get_end_reason());
                CPPUNIT_ASSERT(!loop);

                // detect ip which is occupied by router
                pcap = Pcap_dummy();
                loop = true;

                daw_thread_main_ipv6_non_root("wlan0", parse_ip("2001:470:1f15:df3::1/64"), loop, pcap);

                CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::duplicate_address == pcap.get_end_reason());
                CPPUNIT_ASSERT(!loop);

                // just timeout
                f = std::async(std::launch::async, timeout, std::ref(loop), 1000);
                pcap = Pcap_dummy();
                loop = true;

                daw_thread_main_ipv6_non_root("wlan0", parse_ip("2001:470:1f15:df3::DEAD/64"), loop, pcap);

                CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::unset == pcap.get_end_reason());
                CPPUNIT_ASSERT(!loop);
        }

        void write_ip_neigh_output(std::string const & filename)
        {
                std::ofstream ofile(filename);
                ofile << "2001:470:1f15:ea7::1 dev wlan0 lladdr 00:00:83:8a:20:00 router STALE\n";
                ofile << "fe80::200:83ff:fe8a:2000 dev wlan0 lladdr 00:00:83:8a:20:00 router REACHABLE\n";
                ofile << "192.168.1.181 dev wlan0 lladdr 00:14:38:d3:00:69 STALE\n";
                ofile << "192.168.1.1 dev wlan0 lladdr 00:00:83:8a:20:00 REACHABLE\n";
        }

        void test_has_neighbour_ip() {
                File_descriptor const fd{get_tmp_file("test_dad_has_neighbour_ip_XXXXXX")};
                write_ip_neigh_output(fd.filename);

                CPPUNIT_ASSERT(has_neighbour_ip("wlan0", parse_ip("2001:470:1f15:ea7::1/64"), fd));
                CPPUNIT_ASSERT(has_neighbour_ip("wlan0", parse_ip("fe80::200:83ff:fe8a:2000/64"), fd));
                CPPUNIT_ASSERT(has_neighbour_ip("wlan0", parse_ip("192.168.1.181/24"), fd));
                CPPUNIT_ASSERT(has_neighbour_ip("wlan0", parse_ip("192.168.1.1/24"), fd));

                CPPUNIT_ASSERT(!has_neighbour_ip("eth0", parse_ip("2001:470:1f15:ea7::1/64"), fd));
                CPPUNIT_ASSERT(!has_neighbour_ip("wlan0", parse_ip("2001:470:1f15:ea7::1234/64"), fd));
                CPPUNIT_ASSERT(!has_neighbour_ip("eth0", parse_ip("192.168.1.181/24"), fd));
                CPPUNIT_ASSERT(!has_neighbour_ip("wlan0", parse_ip("192.168.2.181/24"), fd));
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Duplicate_address_watcher_test );

