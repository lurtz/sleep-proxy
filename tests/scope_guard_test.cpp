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

bool file_exists(const std::string& filename);
std::string get_path(const std::string command);

class Scope_guard_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Scope_guard_test );
        CPPUNIT_TEST( test_scope_guard );
        CPPUNIT_TEST( test_temp_ip );
        CPPUNIT_TEST( test_drop_port );
        CPPUNIT_TEST( test_reject_tp );
        CPPUNIT_TEST( test_block_icmp );
        CPPUNIT_TEST( test_file_exists );
        CPPUNIT_TEST( test_get_path );
        CPPUNIT_TEST( test_take_action );
        CPPUNIT_TEST( test_take_action_failed_command );
        CPPUNIT_TEST( test_take_action_non_existing_command );
        CPPUNIT_TEST_SUITE_END();
        public:
        void setUp() {}

        void tearDown() {}

        void test_scope_guard() {
                std::mutex ints_mutex;
                std::vector<int *> ints;
                int x = 123;
                {
                        Scope_guard sg{ptr_guard(ints, ints_mutex, x)};
                        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), ints.size());
                        CPPUNIT_ASSERT_EQUAL(&x, ints.at(0));
                        CPPUNIT_ASSERT_EQUAL(x, *ints.at(0));
                        CPPUNIT_ASSERT_EQUAL(123, x);
                }
                CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), ints.size());
                CPPUNIT_ASSERT_EQUAL(123, x);
                {
                        Scope_guard sg{ptr_guard(ints, ints_mutex, x)};
                        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), ints.size());
                        CPPUNIT_ASSERT_EQUAL(&x, ints.at(0));
                        CPPUNIT_ASSERT_EQUAL(123, x);
                        sg.free();
                        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), ints.size());
                        CPPUNIT_ASSERT_EQUAL(123, x);
                        sg.free();
                        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), ints.size());
                        CPPUNIT_ASSERT_EQUAL(123, x);
                }
                CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), ints.size());
                CPPUNIT_ASSERT_EQUAL(123, x);
                {
                        Scope_guard sg{ptr_guard(ints, ints_mutex, x)};
                        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), ints.size());
                        CPPUNIT_ASSERT_EQUAL(&x, ints.at(0));
                        CPPUNIT_ASSERT_EQUAL(123, x);
                        x = 42;
                        CPPUNIT_ASSERT_EQUAL(x, *ints.at(0));
                        int y = 21;
                        Scope_guard sg2{ptr_guard(ints, ints_mutex, y)};
                        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(2), ints.size());
                        CPPUNIT_ASSERT_EQUAL(&x, ints.at(0));
                        CPPUNIT_ASSERT_EQUAL(&y, ints.at(1));
                        CPPUNIT_ASSERT_EQUAL(21, y);
                        sg.free();
                        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), ints.size());
                        CPPUNIT_ASSERT_EQUAL(&y, ints.at(0));
                }
        }

        void test_temp_ip() {
                IP_address ip = parse_ip("10.0.0.1/16");
                std::string iface{"eth0"};
                Temp_ip ti{iface, ip};
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/ip addr add " + ip.with_subnet() + " dev " + iface), ti(Action::add));
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/ip addr del " + ip.with_subnet() + " dev " + iface), ti(Action::del));

                iface = "even more randomness";
                Temp_ip ti2{iface, ip};
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/ip addr add " + ip.with_subnet() + " dev " + iface), ti2(Action::add));
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/ip addr del " + ip.with_subnet() + " dev " + iface), ti2(Action::del));
        }

        void test_drop_port() {
                IP_address ip = parse_ip("10.0.0.1/16");
                uint16_t port{1234};
                Drop_port op{ip, port};
                CPPUNIT_ASSERT_EQUAL("/sbin/iptables -w -I INPUT -d " + ip.pure() + " -p tcp --syn --dport " + std::to_string(port) + " -j DROP", op(Action::add));
                CPPUNIT_ASSERT_EQUAL("/sbin/iptables -w -D INPUT -d " + ip.pure() + " -p tcp --syn --dport " + std::to_string(port) + " -j DROP", op(Action::del));

                ip = parse_ip("fe80::affe");
                port = 666;
                Drop_port op2{ip, port};
                CPPUNIT_ASSERT_EQUAL("/sbin/ip6tables -w -I INPUT -d " + ip.pure() + " -p tcp --syn --dport " + std::to_string(port) + " -j DROP", op2(Action::add));
                CPPUNIT_ASSERT_EQUAL("/sbin/ip6tables -w -D INPUT -d " + ip.pure() + " -p tcp --syn --dport " + std::to_string(port) + " -j DROP", op2(Action::del));
        }

        void test_reject_tp() {
                IP_address ip = parse_ip("10.0.0.1/16");

                Reject_tp rt{ip, Reject_tp::TP::UDP};
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/iptables -w -I INPUT -d " + ip.pure() + " -p udp -j REJECT"), rt(Action::add));
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/iptables -w -D INPUT -d " + ip.pure() + " -p udp -j REJECT"), rt(Action::del));

                ip = parse_ip("10.0.0.1/16");
                Reject_tp rt2{ip, Reject_tp::TP::TCP};
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/iptables -w -I INPUT -d " + ip.pure() + " -p tcp -j REJECT"), rt2(Action::add));
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/iptables -w -D INPUT -d " + ip.pure() + " -p tcp -j REJECT"), rt2(Action::del));

                ip = parse_ip("2001::dead:affe/16");
                Reject_tp rt3{ip, Reject_tp::TP::TCP};
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/ip6tables -w -I INPUT -d " + ip.pure() + " -p tcp -j REJECT"), rt3(Action::add));
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/ip6tables -w -D INPUT -d " + ip.pure() + " -p tcp -j REJECT"), rt3(Action::del));
        }

        void test_block_icmp() {
                IP_address ip = parse_ip("10.0.0.1/16");

                Block_icmp bi{ip};
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/iptables -w -I OUTPUT -d 10.0.0.1 -p icmp --icmp-type destination-unreachable -j DROP"), bi(Action::add));
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/iptables -w -D OUTPUT -d 10.0.0.1 -p icmp --icmp-type destination-unreachable -j DROP"), bi(Action::del));

                ip = parse_ip("fe80::affe:affe");
                Block_icmp bi2{ip};
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/ip6tables -w -I OUTPUT -d fe80::affe:affe -p icmpv6 --icmpv6-type destination-unreachable -j DROP"), bi2(Action::add));
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/ip6tables -w -D OUTPUT -d fe80::affe:affe -p icmpv6 --icmpv6-type destination-unreachable -j DROP"), bi2(Action::del));
        }

        void test_file_exists() {
                CPPUNIT_ASSERT(file_exists("/dev"));
                CPPUNIT_ASSERT(file_exists("/dev/null"));
                CPPUNIT_ASSERT(file_exists("/etc/fstab"));
                CPPUNIT_ASSERT(!file_exists("/dev/nullfdasfdsafdsafdsa"));
        }

        void test_get_path() {
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/ip"), get_path("ip"));
                CPPUNIT_ASSERT_EQUAL(std::string("/sbin/iptables"), get_path("iptables"));
                CPPUNIT_ASSERT_EQUAL(std::string("/bin/sh"), get_path("sh"));
                CPPUNIT_ASSERT_EQUAL(std::string("/usr/bin/make"), get_path("make"));
        }

        struct Take_action_function {
                const std::string filename;
                std::string operator()(const Action a) {
                        const std::map<Action, std::string> amap{{Action::add, "touch"}, {Action::del, "rm"}};
                        return get_path(amap.at(a)) + " " + filename;
                }
        };

        void test_take_action() {
              const std::string filename{"/tmp/take_action_test_testfile"};
              CPPUNIT_ASSERT(!file_exists(filename));
              {
                      Scope_guard sg{Take_action_function{filename}};
                      CPPUNIT_ASSERT(file_exists(filename));
              }
              CPPUNIT_ASSERT(!file_exists(filename));
        }

        std::string exception_causing_function(const Action&) {
                return get_path("false");
        }

        void test_take_action_failed_command() {
              CPPUNIT_ASSERT_THROW(Scope_guard{[](const Action&){return get_path("false");}}, std::runtime_error);
        }

        void test_take_action_non_existing_command() {
              CPPUNIT_ASSERT_THROW(Scope_guard{[](const Action&){return "falsefalsefalsefalse";}}, std::runtime_error);
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Scope_guard_test );

