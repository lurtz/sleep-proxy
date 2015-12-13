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

#include <string>
#include <netinet/ether.h>
#include <thread>
#include "scope_guard.h"
#include "pcap_wrapper.h"

/** watches if someone else sends a magic wol packet */
struct Wol_watcher {
  ether_addr const mac;
  Pcap_wrapper &waiting_for_syn;

  Pcap_wrapper waiting_for_wol;
  std::thread wol_listener;

  Wol_watcher(std::string const &iface, ether_addr mac,
              Pcap_wrapper &waiting_for_synn);
  ~Wol_watcher();

  std::string operator()(const Action action);

  void stop();
};
