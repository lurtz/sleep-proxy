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

#include "ethernet.h"
#include "ip_utils.h"
#include "log.h"
#include "wol.h"
#include <string>

namespace {
void print_help() { log_string(LOG_NOTICE, "usage: [-i iface] mac"); }

void check_arguments(const int argc, const int count) {
  if (argc < count) {
    print_help();
    exit(1);
  }
}
} // namespace

int main(int argc, char *argv[]) {
  int count = 2;
  unsigned int mac_pos = 1;
  check_arguments(argc, count);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  if (std::string("-i") == argv[1]) {
    count += 2;
    mac_pos += 2;
  }
  check_arguments(argc, count);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  ether_addr mac = mac_to_binary(argv[mac_pos]);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  if (std::string("-i") != argv[1]) {
    wol_udp(mac);
  } else {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    std::string iface = validate_iface(argv[2]);
    static auto const max_ethernet_name_size = uint8_t{13};
    if (iface.size() > max_ethernet_name_size) {
      log_string(LOG_NOTICE,
                 "maximum of 13 characters allowed for ethernet name");
      return 1;
    }

    wol_ethernet(iface, mac);
  }
  return 0;
}
