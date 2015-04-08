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

#include "duplicate_address_watcher.h"
#include "log.h"
#include "container_utils.h"
#include "spawn_process.h"

bool has_neighbour_ip(std::string const &iface, IP_address const &ip,
                      std::vector<std::string> const &content) {
  auto const match_iface_and_ip = [&](std::string const &line) {
    return line.find(iface) != std::string::npos &&
           line.find(ip.pure()) != std::string::npos &&
           line.find("STALE") == std::string::npos &&
           line.find("DELAY") == std::string::npos &&
           line.find("PROBE") == std::string::npos &&
           line.find("FAILED") == std::string::npos;
  };
  return std::any_of(std::begin(content), std::end(content),
                     match_iface_and_ip);
}

Ip_neigh_checker::Ip_neigh_checker()
    : ip_neigh_output{std::make_shared<File_descriptor>(
          get_tmp_file("ip_neigh_outputXXXXXX"))},
      cmd{get_path("ip"), "neigh"} {}

bool Ip_neigh_checker::operator()(std::string const &iface,
                                  IP_address const &ip) const {
  ip_neigh_output->delete_content();
  const pid_t pid = spawn(cmd, "/dev/null", *ip_neigh_output);
  const uint8_t status = wait_until_pid_exits(pid);

  log(LOG_DEBUG, "read %d lines from ip neigh",
      ip_neigh_output->get_content().size());

  return status != 0 ||
         has_neighbour_ip(iface, ip, ip_neigh_output->get_content());
}

void daw_thread_main_non_root(const std::string &iface, const IP_address &ip,
                              Is_ip_occupied const &is_ip_occupied,
                              std::atomic_bool &loop, Pcap_wrapper &pc) {
  // 2. while(loop)
  // 2.1 use 'ip neigh' to watch for neighbors with the same ip
  // 2.2 if someone uses ip
  // 2.2.1 loop = false
  // 2.2.2 pc.break_loop
  log(LOG_DEBUG, "daw_thread_main_non_root: iface = %s, ip = %s, loop = %d",
      iface.c_str(), ip.with_subnet().c_str(), static_cast<bool>(loop));

  while (loop) {
    if (is_ip_occupied(iface, ip)) {
      loop = false;
      pc.break_loop(Pcap_wrapper::Loop_end_reason::duplicate_address);
    } else {
      std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
  }
}

void daw_thread_main_ipv6(const std::string &iface, const IP_address &ip,
                          Is_ip_occupied const &is_ip_occupied,
                          std::atomic_bool &loop, Pcap_wrapper &pc) {
  // 1. block incoming duplicate address detection for ip using firewall
  Scope_guard const bipv6ns{Block_ipv6_neighbor_solicitation{ip}};
  daw_thread_main_non_root(iface, ip, is_ip_occupied, loop, pc);
}

Duplicate_address_watcher::Duplicate_address_watcher(
    const std::string ifacee, const IP_address ipp, Pcap_wrapper &pc,
    Is_ip_occupied const is_ip_occupiedd)
    : iface(std::move(ifacee)), ip(std::move(ipp)), pcap(pc),
      is_ip_occupied{std::move(is_ip_occupiedd)},
      loop(std::make_shared<std::atomic_bool>(false)) {}

Duplicate_address_watcher::~Duplicate_address_watcher() {
  if (loop.use_count() == 1) {
    stop_watcher();
  }
}

typedef std::function<void(const std::string &, const IP_address &,
                           Is_ip_occupied const &, std::atomic_bool &,
                           Pcap_wrapper &)> Main_Function_Type;

std::string Duplicate_address_watcher::operator()(const Action action) {
  // TODO this does not work for ipv6
  if (ip.family == AF_INET6)
    return "";

  Main_Function_Type const main_function =
      ip.family == AF_INET ? daw_thread_main_non_root : daw_thread_main_ipv6;

  if (Action::add == action) {
    log(LOG_INFO, "starting Duplicate_address_watcher for IP %s",
        ip.with_subnet().c_str());
    *loop = true;
    watcher =
        std::make_shared<std::thread>(main_function, iface, ip, is_ip_occupied,
                                      std::ref(*loop), std::ref(pcap));
  }
  if (Action::del == action) {
    log(LOG_INFO, "stopping Duplicate_address_watcher for IP %s",
        ip.with_subnet().c_str());
    stop_watcher();
  }
  return "";
}

void Duplicate_address_watcher::stop_watcher() {
  *loop = false;
  if (watcher != nullptr && watcher->joinable()) {
    watcher->join();
  }
  watcher = nullptr;
}
