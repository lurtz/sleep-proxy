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

#include "wol.h"

#include "ethernet.h"
#include "packet_test_utils.h"

#include <cppunit/extensions/HelperMacros.h>
#include <limits>
#include <netinet/ether.h>
#include <string>
#include <vector>

class Wol_test : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(Wol_test);
  CPPUNIT_TEST(test_create_wol_payload);
  CPPUNIT_TEST_SUITE_END();

public:
  void setUp() override {}
  void tearDown() override {}

  static void check_wol_payload(const std::vector<uint8_t> &wol,
                                const unsigned char start,
                                const unsigned char end_pos) {
    auto data = std::begin(wol);
    const auto end = std::end(wol);
    static auto const ff_repetitions = uint8_t{6};
    for (unsigned int i = 0; i < ff_repetitions && data < end; i++, data++) {
      CPPUNIT_ASSERT_EQUAL(std::numeric_limits<uint8_t>::max(), *data);
    }
    static auto const mac_repetitions = 16;
    for (unsigned int i = 0; i < mac_repetitions; i++) {
      check_range(data, end, start, end_pos);
    }
    CPPUNIT_ASSERT(data == end);
  }

  static void test_create_wol_payload() {
    auto wol_packet = create_wol_payload(mac_to_binary("11:22:33:44:55:66"));
    // NOLINTNEXTLINE
    check_wol_payload(wol_packet, 1, 7);
    wol_packet = create_wol_payload(mac_to_binary("88:99:aA:bB:cc:dd"));
    // NOLINTNEXTLINE
    check_wol_payload(wol_packet, 8, 14);
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(Wol_test);
