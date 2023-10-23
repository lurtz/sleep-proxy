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

#include "scope_guard.h"

#include "spawn_process.h"
#include "to_string.h"

#include <cppunit/extensions/HelperMacros.h>

class Scope_guard_test : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(Scope_guard_test);
  CPPUNIT_TEST(test_scope_guard_constructor);
  CPPUNIT_TEST(test_scope_guard);
  CPPUNIT_TEST(test_scope_guard_with_changed_variable);
  CPPUNIT_TEST(test_ptr_guard);
  CPPUNIT_TEST(test_temp_ip);
  CPPUNIT_TEST(test_drop_port);
  CPPUNIT_TEST(test_reject_tp);
  CPPUNIT_TEST(test_block_icmp);
  CPPUNIT_TEST(test_block_ipv6_neighbor_solicitation_link_local);
  CPPUNIT_TEST(test_block_ipv6_neighbor_solicitation_global_address);
  CPPUNIT_TEST(test_block_ipv6_neighbor_solicitation_with_ipv4);
  CPPUNIT_TEST(test_take_action);
  CPPUNIT_TEST(test_take_action_failed_command);
  CPPUNIT_TEST(test_take_action_non_existing_command);
  CPPUNIT_TEST_SUITE_END();

public:
  void setUp() override {}

  void tearDown() override {}

  static void test_scope_guard_constructor() {
    {
      Scope_guard sg;
      sg.free();
    }
    {
      std::mutex ints_mutex;
      std::vector<int const *> ints;
      static const int x = 123;

      Scope_guard sg{ptr_guard(ints, ints_mutex, x)};
      CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), ints.size());
      CPPUNIT_ASSERT_EQUAL(&x, ints.at(0));

      Scope_guard sg2 = std::move(sg);
      CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), ints.size());
      CPPUNIT_ASSERT_EQUAL(&x, ints.at(0));
      CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), ints.size());
      CPPUNIT_ASSERT_EQUAL(&x, ints.at(0));
      sg2.free();
      CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), ints.size());
    }
  }

  static void test_scope_guard() {
    std::mutex ints_mutex;
    std::vector<int const *> ints;
    static int const x = 123;
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
      CPPUNIT_ASSERT_EQUAL(x, *ints.at(0));
      static const int y = 21;
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

  static void test_scope_guard_with_changed_variable() {
    std::mutex ints_mutex;
    std::vector<int *> ints;
    // NOLINTNEXTLINE
    int x = 123;
    {
      Scope_guard sg{ptr_guard(ints, ints_mutex, x)};
      CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), ints.size());
      CPPUNIT_ASSERT_EQUAL(&x, ints.at(0));
      CPPUNIT_ASSERT_EQUAL(123, x);
      // NOLINTNEXTLINE
      x = 42;
      CPPUNIT_ASSERT_EQUAL(x, *ints.at(0));
    }
    CPPUNIT_ASSERT_EQUAL(42, x);
  }

  static void test_ptr_guard() {
    std::mutex ints_mutex;
    std::vector<int const *> ints;
    static const int x = 123;
    auto guard = ptr_guard(ints, ints_mutex, x);
    CPPUNIT_ASSERT_EQUAL(&ints_mutex, &guard.cont_mutex);
    CPPUNIT_ASSERT_EQUAL(ints, guard.cont);
    CPPUNIT_ASSERT_EQUAL(x, guard.ref);

    CPPUNIT_ASSERT_EQUAL(std::string(), guard(static_cast<Action>(3)));

    CPPUNIT_ASSERT_EQUAL(&ints_mutex, &guard.cont_mutex);
    CPPUNIT_ASSERT_EQUAL(ints, guard.cont);
    CPPUNIT_ASSERT_EQUAL(x, guard.ref);

    CPPUNIT_ASSERT_THROW((void)guard(Action::del), std::runtime_error);
  }

  static void test_temp_ip() {
    IP_address ip = parse_ip("10.0.0.1/16");
    std::string iface{"eth0"};
    Temp_ip ti{iface, ip};
    CPPUNIT_ASSERT_EQUAL("ip addr add " + ip.with_subnet() + " dev " + iface,
                         ti(Action::add));
    CPPUNIT_ASSERT_EQUAL("ip addr del " + ip.with_subnet() + " dev " + iface,
                         ti(Action::del));

    iface = "even more randomness";
    Temp_ip ti2{iface, ip};
    CPPUNIT_ASSERT_EQUAL("ip addr add " + ip.with_subnet() + " dev " + iface,
                         ti2(Action::add));
    CPPUNIT_ASSERT_EQUAL("ip addr del " + ip.with_subnet() + " dev " + iface,
                         ti2(Action::del));
  }

  static void test_drop_port() {
    IP_address ip = parse_ip("10.0.0.1/16");
    static const uint16_t port0{1234};
    Drop_port op{ip, port0};
    CPPUNIT_ASSERT_EQUAL(
        "iptables -w -I INPUT -d " + ip.pure() + " -p tcp --syn --dport " +
            std::to_string(static_cast<uint32_t>(port0)) + " -j DROP",
        op(Action::add));
    CPPUNIT_ASSERT_EQUAL(
        "iptables -w -D INPUT -d " + ip.pure() + " -p tcp --syn --dport " +
            std::to_string(static_cast<uint32_t>(port0)) + " -j DROP",
        op(Action::del));

    ip = parse_ip("fe80::affe");
    static const uint16_t port1 = 666;
    Drop_port op2{ip, port1};
    CPPUNIT_ASSERT_EQUAL(
        "ip6tables -w -I INPUT -d " + ip.pure() + " -p tcp --syn --dport " +
            std::to_string(static_cast<uint32_t>(port1)) + " -j DROP",
        op2(Action::add));
    CPPUNIT_ASSERT_EQUAL(
        "ip6tables -w -D INPUT -d " + ip.pure() + " -p tcp --syn --dport " +
            std::to_string(static_cast<uint32_t>(port1)) + " -j DROP",
        op2(Action::del));
  }

  static void test_reject_tp() {
    IP_address ip = parse_ip("10.0.0.1/16");

    Reject_tp rt{ip, Reject_tp::TP::UDP};
    CPPUNIT_ASSERT_EQUAL("iptables -w -I INPUT -d " + ip.pure() +
                             " -p udp -j REJECT",
                         rt(Action::add));
    CPPUNIT_ASSERT_EQUAL("iptables -w -D INPUT -d " + ip.pure() +
                             " -p udp -j REJECT",
                         rt(Action::del));

    ip = parse_ip("10.0.0.1/16");
    Reject_tp rt2{ip, Reject_tp::TP::TCP};
    CPPUNIT_ASSERT_EQUAL("iptables -w -I INPUT -d " + ip.pure() +
                             " -p tcp -j REJECT",
                         rt2(Action::add));
    CPPUNIT_ASSERT_EQUAL("iptables -w -D INPUT -d " + ip.pure() +
                             " -p tcp -j REJECT",
                         rt2(Action::del));

    ip = parse_ip("2001::dead:affe/16");
    Reject_tp rt3{ip, Reject_tp::TP::TCP};
    CPPUNIT_ASSERT_EQUAL("ip6tables -w -I INPUT -d " + ip.pure() +
                             " -p tcp -j REJECT",
                         rt3(Action::add));
    CPPUNIT_ASSERT_EQUAL("ip6tables -w -D INPUT -d " + ip.pure() +
                             " -p tcp -j REJECT",
                         rt3(Action::del));
  }

  static void test_block_icmp() {
    IP_address ip = parse_ip("10.0.0.1/16");

    Block_icmp bi{ip};
    CPPUNIT_ASSERT_EQUAL(
        std::string("iptables -w -I OUTPUT -d 10.0.0.1 -p icmp "
                    "--icmp-type destination-unreachable -j DROP"),
        bi(Action::add));
    CPPUNIT_ASSERT_EQUAL(
        std::string("iptables -w -D OUTPUT -d 10.0.0.1 -p icmp "
                    "--icmp-type destination-unreachable -j DROP"),
        bi(Action::del));

    ip = parse_ip("fe80::affe:affe");
    Block_icmp bi2{ip};
    CPPUNIT_ASSERT_EQUAL(
        std::string("ip6tables -w -I OUTPUT -d fe80::affe:affe -p icmpv6 "
                    "--icmpv6-type destination-unreachable -j DROP"),
        bi2(Action::add));
    CPPUNIT_ASSERT_EQUAL(
        std::string("ip6tables -w -D OUTPUT -d fe80::affe:affe -p icmpv6 "
                    "--icmpv6-type destination-unreachable -j DROP"),
        bi2(Action::del));
  }

  static std::string
  block_ipv6_neighbor_solicitation_cmd(std::string const &action,
                                       std::string const &rule) {
    std::string const binary{"ip6tables -w -"};
    std::string const options{" INPUT -s :: -p icmpv6 --icmpv6-type "
                              "neighbour-solicitation -m u32 --u32 "};
    std::string const jump{" -j DROP"};
    return binary + action + options + rule + jump;
  }

  static void test_block_ipv6_neighbor_solicitation_link_local() {
    Block_ipv6_neighbor_solicitation const bipv6ns{parse_ip("fe80::123")};

    std::string const rule{"48=0xfe800000&&"
                           "52=0x00000000&&"
                           "56=0x00000000&&"
                           "60=0x00000123"};
    std::string const expected_insert{
        block_ipv6_neighbor_solicitation_cmd("I", rule)};
    std::string const expected_delete{
        block_ipv6_neighbor_solicitation_cmd("D", rule)};

    CPPUNIT_ASSERT_EQUAL(expected_insert, bipv6ns(Action::add));
    CPPUNIT_ASSERT_EQUAL(expected_delete, bipv6ns(Action::del));
  }

  static void test_block_ipv6_neighbor_solicitation_global_address() {
    Block_ipv6_neighbor_solicitation const bipv6ns{
        parse_ip("2a00:1450:4005:800::1004")};

    std::string const rule{"48=0x2a001450&&"
                           "52=0x40050800&&"
                           "56=0x00000000&&"
                           "60=0x00001004"};
    std::string const expected_insert{
        block_ipv6_neighbor_solicitation_cmd("I", rule)};
    std::string const expected_delete{
        block_ipv6_neighbor_solicitation_cmd("D", rule)};

    CPPUNIT_ASSERT_EQUAL(expected_insert, bipv6ns(Action::add));
    CPPUNIT_ASSERT_EQUAL(expected_delete, bipv6ns(Action::del));
  }

  static void test_block_ipv6_neighbor_solicitation_with_ipv4() {
    Block_ipv6_neighbor_solicitation const bipv6ns{parse_ip("192.168.6.6")};

    CPPUNIT_ASSERT_THROW(bipv6ns(Action::add), std::runtime_error);
    CPPUNIT_ASSERT_THROW(bipv6ns(Action::del), std::runtime_error);
  }

  struct Take_action_function {
    const std::string filename;
    std::string operator()(const Action a) {
      const std::map<Action, std::string> amap{{Action::add, "touch"},
                                               {Action::del, "rm"}};
      return amap.at(a) + " " + filename;
    }
  };

  static void test_take_action() {
    const std::string filename{"/tmp/take_action_test_testfile"};
    CPPUNIT_ASSERT(!file_exists(filename));
    {
      Scope_guard sg{Take_action_function{filename}};
      CPPUNIT_ASSERT(file_exists(filename));
    }
    CPPUNIT_ASSERT(!file_exists(filename));
  }

  static void test_take_action_failed_command() {
    CPPUNIT_ASSERT_THROW(Scope_guard{[](const Action &) { return "false"; }},
                         std::runtime_error);
  }

  static void test_take_action_non_existing_command() {
    CPPUNIT_ASSERT_THROW(
        Scope_guard{[](const Action &) { return "falsefalsefalsefalse"; }},
        std::runtime_error);
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(Scope_guard_test);
