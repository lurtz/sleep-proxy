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

#include "pcap_wrapper.h"
#include "scope_guard.h"
#include <cstdint>
#include <netinet/ether.h>
#include <string>
#include <thread>

bool is_magic_packet(std::vector<uint8_t> const &data, ether_addr const &mac);

void break_on_magic_packet(const struct pcap_pkthdr *header,
                           const u_char *packet, ether_addr const &mac,
                           Pcap_wrapper &waiting_for_wol);

void wol_watcher_thread_main(ether_addr const &mac,
                             Pcap_wrapper &waiting_for_wol,
                             Pcap_wrapper &waiting_for_syn);

/** watches if someone else sends a magic wol packet */
struct Wol_watcher {
  ether_addr const mac;
  Pcap_wrapper &waiting_for_syn;

  Pcap_wrapper waiting_for_wol;
  std::thread wol_listener;

  Wol_watcher(std::string const &iface, ether_addr mac,
              Pcap_wrapper &waiting_for_synn);

  Wol_watcher(Wol_watcher const &) = delete;
  Wol_watcher(Wol_watcher &&) = delete;

  ~Wol_watcher();

  Wol_watcher &operator=(Wol_watcher const &) = delete;
  Wol_watcher &operator=(Wol_watcher &&) = delete;

  std::string operator()(Action action);

  void stop();
};
