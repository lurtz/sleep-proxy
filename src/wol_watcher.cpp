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
#include "log.h"
#include "ethernet.h"
#include "wol.h"

bool is_magic_packet(std::vector<uint8_t> const &data, ether_addr const &mac) {
  // 1. put the magic pattern into a string
  std::vector<uint8_t> const packet{create_wol_payload(mac)};
  std::string const packet_string{std::begin(packet), std::end(packet)};
  // 2. convert data into a string
  std::string const data_string{std::begin(data), std::end(data)};
  // 3. search in data string for the magic pattern with string search
  return std::string::npos != data_string.find(packet_string);
}

void break_when_magic_packet_is_found(const struct pcap_pkthdr *header,
                                      const u_char *packet,
                                      ether_addr const &mac,
                                      Pcap_wrapper &waiting_for_wol) {
  if (header == nullptr || packet == nullptr) {
    log_string(LOG_ERR, "header or packet are nullptr");
    return;
  }

  std::vector<uint8_t> const data{packet, packet + header->caplen};
  if (is_magic_packet(data, mac)) {
    waiting_for_wol.break_loop(
        Pcap_wrapper::Loop_end_reason::duplicate_address);
  }
}

void wol_watcher_thread_main(ether_addr const &mac,
                             Pcap_wrapper &waiting_for_wol,
                             Pcap_wrapper &waiting_for_syn) {
  auto const break_on_magic_packet = [&](const struct pcap_pkthdr *header,
                                         const u_char *packet) {
    break_when_magic_packet_is_found(header, packet, mac, waiting_for_wol);
  };

  auto const ler = waiting_for_wol.loop(0, break_on_magic_packet);
  if (Pcap_wrapper::Loop_end_reason::duplicate_address == ler) {
    waiting_for_syn.break_loop(
        Pcap_wrapper::Loop_end_reason::duplicate_address);
  }
}

Wol_watcher::Wol_watcher(std::string const &iface, ether_addr macc,
                         Pcap_wrapper &waiting_for_synn)
    : mac(std::move(macc)), waiting_for_syn{waiting_for_synn},
      waiting_for_wol{iface}, wol_listener{} {
  std::string const filter =
      "udp port 0 or udp port 7 or udp port 9 or ether proto 0x0842 ";
  waiting_for_wol.set_filter(filter);
}

Wol_watcher::~Wol_watcher() { stop(); }

std::string Wol_watcher::operator()(const Action action) {
  if (Action::add == action) {
    log(LOG_INFO, "starting Wol_watcher");
    wol_listener =
        std::thread(wol_watcher_thread_main, std::cref(mac),
                    std::ref(waiting_for_wol), std::ref(waiting_for_syn));
  }
  if (Action::del == action) {
    log(LOG_INFO, "starting Wol_watcher");
    stop();
  }
  return "";
}

void Wol_watcher::stop() {
  waiting_for_wol.break_loop(Pcap_wrapper::Loop_end_reason::unset);
  if (wol_listener.joinable()) {
    wol_listener.join();
  }
}
