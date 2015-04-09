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
#include <algorithm>
#include "spawn_process.h"
#include "container_utils.h"
#include "packet_test_utils.h"

void daw_thread_main_non_root(const std::string &iface, const IP_address &ip,
                              Is_ip_occupied const &is_ip_occupied,
                              std::atomic_bool &loop, Pcap_wrapper &pc);

struct Pcap_dummy : public Pcap_wrapper {
  Pcap_dummy() {}
  Pcap_wrapper::Loop_end_reason get_end_reason() const {
    return loop_end_reason;
  }
};

struct Is_ip_occupied_dummy {
  std::vector<std::tuple<std::string, IP_address>> const occupied;

  Is_ip_occupied_dummy(
      std::vector<std::tuple<std::string, IP_address>> occupiedd)
      : occupied{std::move(occupiedd)} {}

  bool operator()(std::string const &iface, IP_address const &ip) const {
    auto const matches = [&](std::tuple<std::string, IP_address> const &item) {
      return std::make_tuple(iface, ip) == item;
    };
    return std::any_of(std::begin(occupied), std::end(occupied), matches);
  }
};

struct Throwing_ip_occupied_dummy {
  bool operator()(std::string const &, IP_address const &) const {
    throw std::runtime_error("throwing ip occupied dummy throws");
    return false;
  }
};

class Duplicate_address_watcher_test : public CppUnit::TestFixture {

  Is_ip_occupied_dummy const ip_checker{
      std::vector<std::tuple<std::string, IP_address>>{
          std::make_tuple("wlan0", parse_ip("192.168.1.1/24")),
          std::make_tuple("wlan0", parse_ip("2001:470:1f15:df3::1/64"))}};
  Pcap_dummy pcap;
  std::atomic_bool loop;

  CPPUNIT_TEST_SUITE(Duplicate_address_watcher_test);
  CPPUNIT_TEST(test_duplicate_address_watcher_destructor);
  CPPUNIT_TEST(test_copy_constructor);
  CPPUNIT_TEST(test_duplicate_address_watcher_ipv4_ip_not_taken);
  CPPUNIT_TEST(test_duplicate_address_watcher_ipv4_ip_taken);
  CPPUNIT_TEST(test_duplicate_address_watcher_ipv6_ip_not_taken);
  CPPUNIT_TEST(test_duplicate_address_watcher_ipv6_ip_taken);
  CPPUNIT_TEST(test_duplicate_address_watcher_receives_exception_in_thread);
  CPPUNIT_TEST(test_ip_neigh_checker);
  CPPUNIT_TEST_SUITE_END();

public:
  void setUp() {
    pcap = Pcap_dummy();
    loop = true;
  }

  void tearDown() {}

  void test_duplicate_address_watcher_destructor() {
    {
      Duplicate_address_watcher daw{"eth0", parse_ip("10.0.0.1/16"), pcap,
                                    ip_checker};
    }
    {
      Duplicate_address_watcher daw{"eth0", parse_ip("10.0.0.1/16"), pcap,
                                    ip_checker};
      CPPUNIT_ASSERT_EQUAL(std::string(""), daw(Action::add));
    }
    {
      Duplicate_address_watcher daw{"eth0", parse_ip("10.0.0.1/16"), pcap,
                                    ip_checker};
      CPPUNIT_ASSERT(!*daw.loop);
      CPPUNIT_ASSERT(daw.watcher == nullptr);
      CPPUNIT_ASSERT_EQUAL(std::string(""), daw(Action::add));
      CPPUNIT_ASSERT(*daw.loop);
      CPPUNIT_ASSERT(daw.watcher != nullptr);
      CPPUNIT_ASSERT_EQUAL(std::string(""), daw(Action::del));
      CPPUNIT_ASSERT(!*daw.loop);
      CPPUNIT_ASSERT(daw.watcher == nullptr);
    }
  }

  Duplicate_address_watcher create() {
    Duplicate_address_watcher daw{"eth0", parse_ip("127.0.0.1/32"), pcap,
                                  ip_checker};
    CPPUNIT_ASSERT_EQUAL(std::string(), daw(Action::add));
    CPPUNIT_ASSERT(*daw.loop);
    CPPUNIT_ASSERT(daw.watcher != nullptr);
    // disable return value optimization
    return std::move(daw);
  }

  void test_copy_constructor() {
    Duplicate_address_watcher const first_one = create();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    CPPUNIT_ASSERT(*first_one.loop);
    CPPUNIT_ASSERT(first_one.watcher != nullptr);
    CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::unset ==
                   pcap.get_end_reason());
  }

  void test_duplicate_address_watcher_ipv4_ip_not_taken() {
    // ip is not occupied by neighbours
    Duplicate_address_watcher daw{"eth0", parse_ip("10.0.0.1/16"), pcap,
                                  ip_checker};
    CPPUNIT_ASSERT_EQUAL(std::string(""), daw(Action::add));
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto const end_reason = pcap.get_end_reason();
    CPPUNIT_ASSERT_EQUAL(std::string(""), daw(Action::del));
    CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::unset == end_reason);
    CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::unset ==
                   pcap.get_end_reason());
  }

  void test_duplicate_address_watcher_ipv4_ip_taken() {
    // ip is occupied by neighbours
    Duplicate_address_watcher daw2{"wlan0", parse_ip("192.168.1.1/24"), pcap,
                                   ip_checker};
    CPPUNIT_ASSERT_EQUAL(std::string(""), daw2(Action::add));
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto const end_reason = pcap.get_end_reason();
    CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::duplicate_address ==
                   end_reason);
    CPPUNIT_ASSERT_EQUAL(std::string(""), daw2(Action::del));
    CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::duplicate_address ==
                   pcap.get_end_reason());
  }

  static void timeout(std::atomic_bool &loop, size_t const milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
    loop = false;
  }

  void test_duplicate_address_watcher_ipv6_ip_taken() {
    // detect ip which is occupied by router
    auto f = std::async(std::launch::async, timeout, std::ref(loop), 1000);
    daw_thread_main_non_root("wlan0", parse_ip("2001:470:1f15:df3::1/64"),
                             ip_checker, loop, pcap);

    CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::duplicate_address ==
                   pcap.get_end_reason());
    CPPUNIT_ASSERT(!loop);
  }

  void test_duplicate_address_watcher_ipv6_ip_not_taken() {
    // just timeout
    auto f = std::async(std::launch::async, timeout, std::ref(loop), 1000);
    daw_thread_main_non_root("wlan0", parse_ip("2001:470:1f15:df3::DEAD/64"),
                             ip_checker, loop, pcap);

    CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::unset ==
                   pcap.get_end_reason());
    CPPUNIT_ASSERT(!loop);
  }

  void test_duplicate_address_watcher_receives_exception_in_thread() {
    Duplicate_address_watcher daw{"wlan0", parse_ip("192.168.1.1/24"), pcap,
                                  Throwing_ip_occupied_dummy()};
    CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::unset ==
                   pcap.get_end_reason());
    CPPUNIT_ASSERT(!*daw.loop);
    { daw(Action::add); }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::signal ==
                   pcap.get_end_reason());
    CPPUNIT_ASSERT(!*daw.loop);
  }

  void test_ip_neigh_checker() {
    std::vector<std::string> const ip_neigh_content = get_ip_neigh_output();
    Iface_Ips const iface_ips = get_iface_ips(ip_neigh_content);

    std::cout << "iface_ips.size() = " << iface_ips.size() << std::endl;

    Ip_neigh_checker const checker;

    // check for ips which are currently present
    for (auto const &iface_ip : iface_ips) {
      // TODO without root privileges ipv6 is not testable
      if (std::get<1>(iface_ip).family == AF_INET) {
        CPPUNIT_ASSERT(checker(std::get<0>(iface_ip), std::get<1>(iface_ip)));
      }
    }

    // check for ips which are not present
    std::set<std::string> ifaces{"eth0", "eth1", "wlan0", "wlan1"};
    std::set<IP_address> ips{parse_ip("10.1.2.3"), parse_ip("192.168.2.2"),
                             parse_ip("fe80::123"), parse_ip("dead::beef"),
                             parse_ip("fe80::dead:beef")};

    for (auto const &iface_ip : iface_ips) {
      ifaces.insert(std::get<0>(iface_ip));
      ips.insert(std::get<1>(iface_ip));
    }
    Iface_Ips not_present_ips = cartesian_product(ifaces, ips);

    auto const new_end =
        std::remove_if(std::begin(not_present_ips), std::end(not_present_ips),
                       [&](Iface_Ips::value_type const &iface_ip) {
          return std::end(iface_ips) != std::find(std::begin(iface_ips),
                                                  std::end(iface_ips),
                                                  iface_ip);
        });
    not_present_ips.resize(static_cast<std::size_t>(
        std::distance(std::begin(not_present_ips), new_end)));

    std::cout << "not_present_ips.size() == " << not_present_ips.size()
              << std::endl;

    for (auto const &iface_ip : not_present_ips) {
      // TODO without root privileges ipv6 is not testable
      if (std::get<1>(iface_ip).family == AF_INET) {
        CPPUNIT_ASSERT(!checker(std::get<0>(iface_ip), std::get<1>(iface_ip)));
      }
    }
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(Duplicate_address_watcher_test);
