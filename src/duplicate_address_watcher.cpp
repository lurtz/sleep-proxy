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
#include <cctype>

std::string get_mac(std::string const &iface) {
  auto const cmd = split(get_path("ip") + " a show dev " + iface, ' ');
  auto const out_in = get_self_pipes(false);
  pid_t const pid = spawn(cmd, File_descriptor(), std::get<1>(out_in));
  uint8_t const status = wait_until_pid_exits(pid);
  if (status != 0) {
    throw std::runtime_error(std::string("get_mac(): ip a show dev ") + iface +
                             " did not succeed");
  }
  auto const lines = std::get<0>(out_in).read();
  auto const line = lines.at(1);
  auto const splitted_line = split(line, ' ');
  return splitted_line.at(5);
}

bool contains_mac_different_from_given(std::string mac,
                                       std::vector<std::string> const &lines) {
  auto const transform_to_upper = [](std::string tmp) {
    std::transform(std::begin(tmp), std::end(tmp), std::begin(tmp), ::toupper);
    return tmp;
  };

  auto const macs_are_not_equal = [&](std::string const &line) {
    return transform_to_upper(line) != mac;
  };

  mac = transform_to_upper(mac);

  return std::any_of(std::begin(lines), std::end(lines), macs_are_not_equal);
}

std::vector<std::string> const get_cmd_ipv4() {
  return std::vector<std::string>{
      get_path("arping"), "-q", "-D", "-c", "1", "-I"};
}

std::vector<std::string> get_cmd_ipv6() {
  return std::vector<std::string>{get_path("ndisc6"), "-q", "-n", "-m"};
}

Ip_neigh_checker::Ip_neigh_checker(std::string mac)
    : this_nodes_mac{std::move(mac)} {}

bool Ip_neigh_checker::is_ipv4_present(std::string const &iface,
                                       IP_address const &ip) const {
  auto cmd_ipv4_tmp = get_cmd_ipv4();
  cmd_ipv4_tmp.push_back(iface);
  cmd_ipv4_tmp.push_back(ip.pure());
  const pid_t pid = spawn(cmd_ipv4_tmp);
  const uint8_t status = wait_until_pid_exits(pid);
  // if arping detects duplicate address, it returns 1
  return status == 1;
}

bool Ip_neigh_checker::is_ipv6_present(std::string const &iface,
                                       IP_address const &ip) const {
  // when multiple nodes have the same ipv6 address
  // lutz@barcas:~/workspace/sleep-proxy$ ndisc6 -q -n -m fe80::123 wlan0
  // A0:88:B4:CF:50:94
  // 22:4E:7F:6F:78:F1
  // ...
  // openwrt handles this differently, and outputs only foreign MACs with an
  // error code. to be able to do tests, I have to check the output if there
  // are foreign macs in it
  auto cmd_ipv6_tmp = get_cmd_ipv6();
  cmd_ipv6_tmp.push_back(ip.pure());
  cmd_ipv6_tmp.push_back(iface);

  auto const out_in = get_self_pipes(false);

  const pid_t pid = spawn(cmd_ipv6_tmp, File_descriptor(), std::get<1>(out_in));
  wait_until_pid_exits(pid);

  // if there are more than one line, there must be another host
  // one line is this programm/node
  return contains_mac_different_from_given(this_nodes_mac,
                                           std::get<0>(out_in).read());
}

bool Ip_neigh_checker::operator()(std::string const &iface,
                                  IP_address const &ip) const {
  if (ip.family == AF_INET) {
    return is_ipv4_present(iface, ip);
  }
  return is_ipv6_present(iface, ip);
}

void daw_thread_main_non_root(const std::string &iface, const IP_address &ip,
                              Is_ip_occupied const &is_ip_occupied,
                              std::atomic_bool &loop, Pcap_wrapper &pc) {
  // 2. while(loop)
  // 2.1 use 'ip neigh' to watch for neighbors with the same ip
  // 2.2 if someone uses ip
  // 2.2.1 loop = false
  // 2.2.2 pc.break_loop
  try {
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
  } catch (std::exception const &e) {
    log(LOG_INFO, "daw_thread_main_non_root got exception: %s", e.what());
    loop = false;
    pc.break_loop(Pcap_wrapper::Loop_end_reason::signal);
  }
}

void daw_thread_main_ipv6(const std::string &iface, const IP_address &ip,
                          Is_ip_occupied const &is_ip_occupied,
                          std::atomic_bool &loop, Pcap_wrapper &pc) {
  // 1. block incoming duplicate address detection for ip using firewall
  try {
    Scope_guard const bipv6ns{Block_ipv6_neighbor_solicitation{ip}};
    daw_thread_main_non_root(iface, ip, is_ip_occupied, loop, pc);
  } catch (std::exception const &e) {
    log(LOG_INFO, "daw_thread_main_ipv6 got exception: %s", e.what());
    loop = false;
    pc.break_loop(Pcap_wrapper::Loop_end_reason::signal);
  }
}

Duplicate_address_watcher::Duplicate_address_watcher(const std::string ifacee,
                                                     const IP_address ipp,
                                                     Pcap_wrapper &pc)
    : iface(std::move(ifacee)), ip(std::move(ipp)), pcap(pc),
      is_ip_occupied{Ip_neigh_checker{get_mac(iface)}}, watcher(nullptr),
      loop(std::make_shared<std::atomic_bool>(false)) {}

Duplicate_address_watcher::Duplicate_address_watcher(
    const std::string ifacee, const IP_address ipp, Pcap_wrapper &pc,
    Is_ip_occupied const is_ip_occupiedd)
    : iface(std::move(ifacee)), ip(std::move(ipp)), pcap(pc),
      is_ip_occupied{std::move(is_ip_occupiedd)}, watcher(nullptr),
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
