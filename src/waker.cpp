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

#include <string>
#include "wol.h"
#include "ip_utils.h"
#include "log.h"
#include "ethernet.h"

void print_help() {
        log_string(LOG_NOTICE, "usage: [-i iface] mac");
}

void check_arguments(const int argc, const int count) {
        if (argc < count) {
                print_help();
                exit(1);
        }
}

int main(int argc, char * argv[]) {
        int count = 2;
        unsigned int mac_pos = 1;
        check_arguments(argc, count);
        if (std::string("-i") == argv[1]) {
                count+=2;
                mac_pos += 2;
        }
        check_arguments(argc, count);
        ether_addr mac = mac_to_binary(validate_mac(argv[mac_pos]));
        if (std::string("-i") != argv[1]) {
                wol_udp(mac);
        } else {
                std::string iface = validate_iface(argv[2]);
                if (iface.size() > 13) {
                        log_string(LOG_NOTICE, "maximum of 13 characters allowed for ethernet name");
                        return 1;
                }

                wol_ethernet(iface, mac);
        }
        return 0;
}

