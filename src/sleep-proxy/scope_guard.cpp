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

#include "scope_guard.h"
#include "container_utils.h"
#include "int_utils.h"
#include "ip_utils.h"
#include "log.h"
#include "spawn_process.h"
#include "to_string.h"
#include <arpa/inet.h>
#include <cerrno>

namespace {
/**
 * ipv4 and ipv6 have different iptables commands. return the one matching
 * the version of ip
 */
std::string get_iptables_cmd(const IP_address &ip) {
  std::string const iptcmd{ip.family == AF_INET ? "iptables" : "ip6tables"};
  return iptcmd;
}

std::string iptables_action(const Action &action) {
  return action == Action::add ? std::string{"I"} : std::string{"D"};
}

/**
 * in iptables the icmp parameter is differenct for IPv4 and IPv6. return
 * the correct one according to the ip version
 */
std::string get_icmp_version(const IP_address &ip) {
  return ip.family == AF_INET ? "icmp" : "icmpv6";
}

std::string ipv6_to_u32_rule(IP_address const &ip) {
  if (ip.family != AF_INET6) {
    throw std::runtime_error(
        "cannot convert ipv4 address into u32 ip6tables rule");
  }

  // only up to 9 && are allored in a --u32 rule, do it as 32bit integers
  // from fe80::123
  // to   -m u32 --u32 48=0xfe800000 && 52=0x0 && 56=0x0 && 60=0x123

  uint32_t const base = 48;
  uint32_t const step = 4;
  uint32_t pos = 0;
  auto const address_int_to_rule = [&](uint32_t ipv6_int) {
    return to_string(base + step * (pos++)) + "=0x" +
           uint32_t_to_eight_hex_chars(ipv6_int);
  };
  std::vector<uint32_t> const ipv6_address{
      std::begin(ip.address.ipv6.s6_addr32),
      std::end(ip.address.ipv6.s6_addr32)};
  std::string const rule = join(ipv6_address, address_int_to_rule, "&&");

  return " -m u32 --u32 " + rule;
}
} // namespace

Scope_guard::Scope_guard() : freed{true}, aquire_release{} {}

Scope_guard::Scope_guard(Aquire_release aquire_release_arg)
    : freed{false}, aquire_release(std::move(aquire_release_arg)) {
  take_action(Action::add);
}

Scope_guard::Scope_guard(Scope_guard &&rhs) noexcept
    : freed{rhs.freed}, aquire_release(rhs.aquire_release) {
  rhs.freed = true;
}

Scope_guard::~Scope_guard() { free(); }

void Scope_guard::free() {
  if (!freed) {
    take_action(Action::del);
    freed = true;
  }
}

void Scope_guard::take_action(const Action a) const {
  std::string cmd = aquire_release(a);
  if (!cmd.empty()) {
    log_string(LOG_INFO, cmd);
    auto const status = spawn(split(cmd, ' '));
    if (status != 0) {
      throw std::runtime_error("command failed: " + cmd);
    }
  }
}

std::string Temp_ip::operator()(const Action action) const {
  auto const saction =
      action == Action::add ? std::string{"add"} : std::string{"del"};
  return std::string{"ip"} + " addr " + saction + " " + ip.with_subnet() +
         " dev " + iface;
}

std::string Drop_port::operator()(const Action action) const {
  const std::string saction{iptables_action(action)};
  const std::string iptcmd = get_iptables_cmd(ip);
  const std::string pip = ip.pure();
  return iptcmd + " -w -" + saction + " INPUT -d " + pip +
         " -p tcp --syn --dport " + to_string(port) + " -j DROP";
}

std::string Reject_tp::operator()(const Action action) const {
  const std::string saction{iptables_action(action)};
  auto const stp = tcp_udp == TP::TCP ? std::string{"tcp"} : std::string{"udp"};
  const std::string iptcmd = get_iptables_cmd(ip);
  const std::string pip = ip.pure();
  return iptcmd + " -w -" + saction + " INPUT -d " + pip + " -p " + stp +
         " -j REJECT";
}

std::string Block_icmp::operator()(const Action action) const {
  const std::string saction{iptables_action(action)};
  const std::string iptcmd = get_iptables_cmd(ip);
  const std::string icmpv = get_icmp_version(ip);
  return iptcmd + " -w -" + saction + " OUTPUT -d " + ip.pure() + " -p " +
         icmpv + " --" + icmpv + "-type destination-unreachable -j DROP";
}

std::string
Block_ipv6_neighbor_solicitation::operator()(const Action action) const {
  const std::string saction{iptables_action(action)};
  const std::string iptcmd{get_iptables_cmd(ip)};
  const std::string ip_rule{ipv6_to_u32_rule(ip)};

  // blocks neighbor solicitation for fe80::123
  // ip6tables -I INPUT -s :: -p icmpv6 --icmpv6-type neighbour-solicitation -m
  // u32 --u32 "48=0xfe800000 && 52=0x0 && 56=0x0 && 60=0x123" -j DROP
  // we also need to match the ipv6 address using u32 ip6tables modul
  return iptcmd + " -w -" + saction +
         " INPUT -s :: -p icmpv6 --icmpv6-type neighbour-solicitation" +
         ip_rule + " -j DROP";
}
