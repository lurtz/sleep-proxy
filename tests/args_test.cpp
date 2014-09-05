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
#include <algorithm>
#include <unistd.h>

#include "args.h"
#include "args_test_interface.h"
#include "to_string.h"
#include "split.h"

class Args_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Args_test );
        CPPUNIT_TEST( test_interface );
        CPPUNIT_TEST( test_addresses );
        CPPUNIT_TEST( test_ports );
        CPPUNIT_TEST( test_mac );
        CPPUNIT_TEST( test_hostname );
        CPPUNIT_TEST( test_ping_tries );
        CPPUNIT_TEST( test_syslog );
        CPPUNIT_TEST( test_read_file );
        CPPUNIT_TEST_SUITE_END();
        std::string interface;
        std::string addresses;
        std::string ports;
        std::string mac;
        std::string hostname;
        std::string ping_tries;
        bool syslog__;
        public:
        void setUp() {
                reset();
                interface = "eth0";
                addresses = "192.168.1.1/24,fe80::affe:123/64";
                ports = "1,2,3456";
                mac = "AF:FE:DE:AD:BE:EF";
                hostname = "router";
                ping_tries = "9001";
                syslog__ = false;
                compare(get_args());
        }

        std::vector<Args> get_args(std::vector<std::string>& params) const {
                // reset getopt() to the start
                optind = 0;
                return read_commandline(static_cast<int>(params.size()), const_cast<char * const *>(get_c_string_array(params).data()));
        }

        Args get_args() const {
                std::vector<std::string> params{"args_test", "-i", interface, "-a", addresses, "-p", ports, "-m", mac, "-n", hostname, "-t", ping_tries};
                if (syslog__) {
                        std::cout << "syslog" << std::endl;
                        params.push_back("--syslog");
                }
                return get_args(params).at(0);
        }

        std::vector<Args> get_args(const std::string& filename, const bool with_syslog = false) const {
                std::vector<std::string> params{"args_test", "-c", filename};
                if (with_syslog) {
                        params.insert(std::begin(params) + 1, "-s");
                }
                return get_args(params);
        }

        std::vector<uint16_t> parse_ports() const {
                std::vector<std::string> split_port = split(ports, ',');
                std::vector<uint16_t> ret_val(split_port.size());
                std::transform(std::begin(split_port), std::end(split_port), std::begin(ret_val), [](const std::string& s){return std::stoi(s);});
                return ret_val;
        }

        void compare(const Args& args) const {
                CPPUNIT_ASSERT_EQUAL(interface, args.interface);
                CPPUNIT_ASSERT(split(addresses, ',') == args.address);
                CPPUNIT_ASSERT(parse_ports() == args.ports);
                std::string upper_mac = mac;
                std::transform(std::begin(upper_mac), std::end(upper_mac), std::begin(upper_mac), [](int ch){return std::toupper(ch);});
                CPPUNIT_ASSERT_EQUAL(upper_mac, args.mac);
                CPPUNIT_ASSERT_EQUAL(hostname, args.hostname);
                CPPUNIT_ASSERT_EQUAL(static_cast<unsigned int>(std::stoul(ping_tries)), args.ping_tries);
                CPPUNIT_ASSERT_EQUAL(syslog__, args.syslog);
        }

        void tearDown() {}

        void test_interface() {
                interface = "lo";
                compare(get_args());
                interface = "lo,eth0";
                CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
                interface = "eth0;";
                CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
        }

        void test_addresses() {
                addresses = "192.168.1.1";
                Args args(get_args());
                addresses = "192.168.1.1/24";
                compare(args);
                addresses = "::1";
                Args args1(get_args());
                addresses = "::1/128";
                compare(args1);
                addresses = "::1/128;";
                CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
                addresses = "";
                CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
        }

        void test_ports() {
                ports = "123";
                compare(get_args());
                ports = "123456789";
                CPPUNIT_ASSERT_THROW(get_args(), std::out_of_range);
                ports = "66000";
                CPPUNIT_ASSERT_THROW(get_args(), std::out_of_range);
                ports = "12345;";
                CPPUNIT_ASSERT_THROW(get_args(), std::invalid_argument);
                ports = "garbage";
                CPPUNIT_ASSERT_THROW(get_args(), std::invalid_argument);
                ports = "";
                CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
        }

        void test_mac() {
                mac = "aa:aa:aa:aa:bb:cc";
                Args args = get_args();
                mac = "AA:AA:AA:AA:BB:CC";
                compare(args);
                mac = "";
                CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
        }

        void test_hostname() {
                hostname = "asdf,.-";
                CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
                hostname = "";
                CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
        }

        void test_ping_tries() {
                ping_tries = "1111111111111111111111";
                CPPUNIT_ASSERT_THROW(get_args(), std::out_of_range);
                ping_tries = "";
                CPPUNIT_ASSERT_THROW(get_args(), std::invalid_argument);
        }

        void test_syslog() {
                syslog__ = true;
                auto args = get_args();
                compare(args);
        }

        void test_read_file() {
                auto args = get_args("../watchhosts");
                CPPUNIT_ASSERT_EQUAL(static_cast<unsigned long>(2), args.size());
                interface = "lo";
                addresses = "10.0.0.1/16,fe80::123/64";
                ports = "12345,23456";
                mac = "01:12:34:45:67:89";
                hostname = "test.lan";
                ping_tries = "5";
                compare(args.at(0));

                interface = "lo";
                addresses = "10.1.2.3/16,fe80::de:ad/64";
                ports = "22";
                mac = "FF:EE:DD:CC:BB:AA";
                hostname = "test2";
                ping_tries = "1";
                compare(args.at(1));

                auto args2 = get_args("../watchhosts-empty");
                CPPUNIT_ASSERT_EQUAL(static_cast<unsigned long>(0), args2.size());

                auto args3 = get_args("../watchhosts", true);
                CPPUNIT_ASSERT_EQUAL(true, args3.at(0).syslog);
                CPPUNIT_ASSERT_EQUAL(true, args3.at(1).syslog);
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Args_test );

