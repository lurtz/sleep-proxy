// Copyright (C) 2015  Lutz Reinhardt
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

#include "wol_watcher.h"

#include "packet_test_utils.h"
#include "wol.h"

#include <cppunit/extensions/HelperMacros.h>
#include <limits>
#include <random>

namespace {
std::vector<uint8_t> gen_random_data(size_t const size) {
  std::default_random_engine generator;
  std::uniform_int_distribution<uint8_t> distribution(
      std::numeric_limits<uint8_t>::min(), std::numeric_limits<uint8_t>::max());

  std::vector<uint8_t> data(size);
  for (uint8_t &i : data) {
    i = distribution(generator);
  }
  return data;
}

pcap_pkthdr create_header(size_t packet_length) {
  const struct pcap_pkthdr header {
    {0, 0}, 0, static_cast<uint32_t>(packet_length)
  };
  return header;
}
} // namespace

class Wol_watcher_test : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(Wol_watcher_test);
  CPPUNIT_TEST(test_is_magic_packet);
  CPPUNIT_TEST(test_break_on_magic_packet);
  CPPUNIT_TEST(test_wol_watcher_thread_main);
  CPPUNIT_TEST_SUITE_END();

  ether_addr const mac0 = mac_to_binary("01:45:12:78:af:bd");
  ether_addr const mac1 = mac_to_binary("33:12:ab:de:56:81");

public:
  void test_is_magic_packet() {
    auto const payload = create_wol_payload(mac0);
    // put it between some random data
    // NOLINTNEXTLINE
    for (size_t iterations = 1; iterations < 102; iterations += 10) {
      for (size_t i = 0; i < iterations; i++) {
        auto data =
            gen_random_data(i) + payload + gen_random_data(iterations - i);
        CPPUNIT_ASSERT(is_magic_packet(data, mac0));
        CPPUNIT_ASSERT(!is_magic_packet(data, mac1));
      }
    }
  }

  void test_break_on_magic_packet() {
    std::vector<uint8_t> const packet =
        gen_random_data(10) + create_wol_payload(mac0) + gen_random_data(10);
    const struct pcap_pkthdr header = create_header(packet.size());
    Pcap_dummy wait_on_wol;

    // check the baseline
    CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::unset ==
                   wait_on_wol.get_end_reason());

    // magic packet with correct mac
    break_on_magic_packet(&header, packet.data(), mac0, wait_on_wol);
    CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::duplicate_address ==
                   wait_on_wol.get_end_reason());

    wait_on_wol = Pcap_dummy();
    CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::unset ==
                   wait_on_wol.get_end_reason());

    // header is nullptr does nothing
    break_on_magic_packet(nullptr, packet.data(), mac0, wait_on_wol);
    CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::unset ==
                   wait_on_wol.get_end_reason());

    // data is nullptr does nothing
    break_on_magic_packet(&header, nullptr, mac0, wait_on_wol);
    CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::unset ==
                   wait_on_wol.get_end_reason());

    // no magic packet
    // NOLINTNEXTLINE
    auto usual_packet = gen_random_data(500);
    while (is_magic_packet(usual_packet, mac0)) {
      // NOLINTNEXTLINE
      usual_packet = gen_random_data(500);
    }
    auto const usual_header = create_header(usual_packet.size());
    break_on_magic_packet(&usual_header, usual_packet.data(), mac0,
                          wait_on_wol);
    CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::unset ==
                   wait_on_wol.get_end_reason());

    // magic packet with another mac
    auto const other_magic_packet =
        gen_random_data(50) + create_wol_payload(mac1) + gen_random_data(50);
    auto const magic_header = create_header(other_magic_packet.size());
    break_on_magic_packet(&magic_header, other_magic_packet.data(), mac0,
                          wait_on_wol);
    CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::unset ==
                   wait_on_wol.get_end_reason());
  }

  void test_wol_watcher_thread_main() {
    Pcap_dummy wait_on_wol;
    Pcap_dummy wait_on_syn;

    CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::unset ==
                   wait_on_syn.get_end_reason());

    wait_on_wol.set_loop_return(
        Pcap_wrapper::Loop_end_reason::packets_captured);
    wol_watcher_thread_main(mac0, wait_on_wol, wait_on_syn);
    CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::unset ==
                   wait_on_syn.get_end_reason());

    wait_on_wol.set_loop_return(
        Pcap_wrapper::Loop_end_reason::duplicate_address);
    wol_watcher_thread_main(mac0, wait_on_wol, wait_on_syn);
    CPPUNIT_ASSERT(Pcap_wrapper::Loop_end_reason::duplicate_address ==
                   wait_on_syn.get_end_reason());
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(Wol_watcher_test);
