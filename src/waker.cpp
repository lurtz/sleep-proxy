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

#include "error_suppression.h"
#include "ethernet.h"
#include "ip_utils.h"
#include "log.h"
#include "wol.h"
#include <cstddef>
#include <cstdlib>
#include <span>
#include <string>

namespace {
void print_help() { log_string(LOG_NOTICE, "usage: [-i iface] mac"); }

void check_arguments(const int argc, const int count) {
  if (argc < count) {
    print_help();
    exit(EXIT_FAILURE);
  }
}
} // namespace

int main(int argc, char *argv[]) {
  int count = 2;
  unsigned int mac_pos = 1;
  check_arguments(argc, count);
  IGNORE_CLANG_WARNING
  std::span<char *> const args{argv, static_cast<size_t>(argc)};
  REENABLE_CLANG_WARNING
  if (std::string("-i") == args[1]) {
    count += 2;
    mac_pos += 2;
  }
  check_arguments(argc, count);
  ether_addr mac = mac_to_binary(args[mac_pos]);
  if (std::string("-i") != args[1]) {
    wol_udp(mac);
  } else {
    std::string iface = validate_iface(args[2]);
    static auto const max_ethernet_name_size = uint8_t{13};
    if (iface.size() > max_ethernet_name_size) {
      log_string(LOG_NOTICE,
                 "maximum of 13 characters allowed for ethernet name");
      return 1;
    }

    wol_ethernet(iface, mac);
  }
  return EXIT_SUCCESS;
}
