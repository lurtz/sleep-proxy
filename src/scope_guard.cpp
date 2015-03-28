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
#include <arpa/inet.h>
#include <cerrno>
#include "log.h"
#include "to_string.h"
#include "ip_utils.h"
#include "spawn_process.h"
#include "container_utils.h"
#include "int_utils.h"

Scope_guard::Scope_guard() : freed{true}, aquire_release{} {
}

Scope_guard::Scope_guard(std::function<std::string(const Action)>&& aquire_release_arg) : freed{false}, aquire_release(std::move(aquire_release_arg)) {
        take_action(Action::add);
}

Scope_guard::Scope_guard(Scope_guard&& rhs) : freed{std::move(rhs.freed)}, aquire_release(std::move(rhs.aquire_release)) {
        rhs.freed = true;
}

Scope_guard::~Scope_guard() {
        free();
}

void Scope_guard::free() {
        if (!freed) {
                take_action(Action::del);
                freed = true;
        }
}

void Scope_guard::take_action(const Action a) const {
        std::string cmd = aquire_release(a);
        if (cmd.size() > 0 ) {
                log_string(LOG_INFO, cmd);
                pid_t pid = spawn(split(cmd, ' '), "/dev/null");
                uint8_t status = wait_until_pid_exits(pid);
                if (status != 0) {
                        throw std::runtime_error("command failed: " + cmd);
                }
        }
}

std::string Temp_ip::operator()(const Action action) const {
        const std::string saction{action == Action::add ? "add" : "del"};
        return get_path("ip") + " addr " + saction + " " + ip.with_subnet() + " dev " + iface;
}

/**
 * ipv4 and ipv6 have different iptables commands. return the one matching
 * the version of ip
 */
std::string get_iptables_cmd(const IP_address& ip) {
        std::string const iptcmd{ip.family == AF_INET ? "iptables" : "ip6tables"};
        return get_path(iptcmd);
}

std::string iptables_action(const Action& action) {
        return action == Action::add ? "I" : "D";
}

std::string Drop_port::operator()(const Action action) const {
        const std::string saction{iptables_action(action)};
        const std::string iptcmd = get_iptables_cmd(ip);
        const std::string pip = ip.pure();
        return iptcmd + " -w -" + saction + " INPUT -d " + pip + " -p tcp --syn --dport " + to_string(port) + " -j DROP";
}

std::string Reject_tp::operator()(const Action action) const {
        const std::string saction{iptables_action(action)};
        const std::string stp{tcp_udp == TP::TCP ? "tcp" : "udp"};
        const std::string iptcmd = get_iptables_cmd(ip);
        const std::string pip = ip.pure();
        return iptcmd + " -w -" + saction + " INPUT -d " + pip + " -p " + stp + " -j REJECT";
}

/**
 * in iptables the icmp parameter is differenct for IPv4 and IPv6. return
 * the correct one according to the ip version
 */
std::string get_icmp_version(const IP_address& ip) {
        return ip.family == AF_INET ? "icmp" : "icmpv6";
}

std::string Block_icmp::operator()(const Action action) const {
        const std::string saction{iptables_action(action)};
        const std::string iptcmd = get_iptables_cmd(ip);
        const std::string icmpv = get_icmp_version(ip);
        return iptcmd + " -w -" + saction + " OUTPUT -d " + ip.pure() + " -p " + icmpv + " --" + icmpv + "-type destination-unreachable -j DROP";
}

std::string ipv6_to_u32_rule(IP_address const & ip) {
        if (ip.family != AF_INET6 ) {
                throw std::runtime_error("cannot convert ipv4 address into u32 ip6tables rule");
        }

        // from fe80::123
        // to   -m u32 --u32 48=0xfe800000 && 52=0x0 && 56=0x0 && 60=0x123

        uint8_t pos = 48;
        auto const address_byte_to_rule = [&](uint8_t ipv6_byte) { return to_string(static_cast<uint32_t>(pos++)) + "=0x" + one_byte_to_two_hex_chars(ipv6_byte); };
        std::vector<uint8_t> const ipv6_address{std::begin(ip.address.ipv6.s6_addr), std::end(ip.address.ipv6.s6_addr)};
        std::string const rule = join(ipv6_address, address_byte_to_rule, " && ");

        return " -m u32 --u32 " + rule;
}

std::string Block_ipv6_neighbor_solicitation::operator()(const Action action) const {
        const std::string saction{iptables_action(action)};
        const std::string iptcmd{get_iptables_cmd(ip)};
        const std::string ip_rule{ipv6_to_u32_rule(ip)};

        // blocks neighbor solicitation for fe80::123
        // ip6tables -I INPUT -s :: -p icmpv6 --icmpv6-type neighbour-solicitation -m u32 --u32 "48=0xfe800000 && 52=0x0 && 56=0x0 && 60=0x123" -j DROP
        // we also need to match the ipv6 address using u32 ip6tables modul
        return iptcmd + " -w -" + saction + " INPUT -s :: -p icmpv6 --icmpv6-type neighbour-solicitation" + ip_rule + " -j DROP";
}

void daw_thread_main_ipv4(const std::string iface, const IP_address ip, std::atomic_bool& loop, Pcap_wrapper& pc) {
        const std::string cmd = get_path("arping") + " -q -D -c 1 -I " + iface + " " + ip.pure();
        log_string(LOG_INFO, "starting: " + cmd);
        auto cmd_split = split(cmd, ' ');
        while (loop) {
                const pid_t pid = spawn(cmd_split, "/dev/null");
                const uint8_t status = wait_until_pid_exits(pid);
                if (status == 1) {
                        loop = false;
                        pc.break_loop(Pcap_wrapper::Loop_end_reason::duplicate_address);
                }
        }
}

bool has_neighbour_ip(std::string const & iface, IP_address const & ip, File_descriptor const & ip_neigh_output) {
        std::vector<std::string> const content = ip_neigh_output.get_content();

        for (std::string const & line : content) {
                if (line.find(iface) == std::string::npos
                                || line.find(ip.pure()) == std::string::npos) {
                        continue;
                } else {
                        return true;
                }
        }

        return false;
}

void daw_thread_main_ipv6_non_root(const std::string & iface, const IP_address & ip, std::atomic_bool & loop, Pcap_wrapper & pc) {
        File_descriptor const ip_neigh_output{get_tmp_file("ip_neigh_outputXXXXXX")};
        std::string const cmd = get_path("ip") + " neigh";
        auto const cmd_split = split(cmd, ' ');
        while (loop) {
                ip_neigh_output.delete_content();
                const pid_t pid = spawn(cmd_split, "/dev/null", ip_neigh_output);
                const uint8_t status = wait_until_pid_exits(pid);

                if (status != 0 || has_neighbour_ip(iface, ip, ip_neigh_output)) {
                        loop = false;
                        pc.break_loop(Pcap_wrapper::Loop_end_reason::duplicate_address);
                }
        }
}

void daw_thread_main_ipv6(const std::string iface, const IP_address ip, std::atomic_bool& loop, Pcap_wrapper& pc) {
        // 1. block incoming duplicate address detection for ip using firewall
        // 2. while(loop)
        // 2.1 use 'ip neigh' to watch for neighbors with the same ip
        // 2.2 if someone uses ip
        // 2.2.1 loop = false
        // 2.2.2 pc.break_loop
        Scope_guard const bipv6ns{Block_ipv6_neighbor_solicitation{ip}};
        daw_thread_main_ipv6_non_root(iface, ip, loop, pc);
}

Duplicate_address_watcher::Duplicate_address_watcher(const std::string ifacee, const IP_address ipp, Pcap_wrapper& pc) : iface(std::move(ifacee)), ip(std::move(ipp)), pcap(pc), loop(std::make_shared<std::atomic_bool>(false)) {
}

typedef std::function<void(const std::string, const IP_address, std::atomic_bool&, Pcap_wrapper&)> Main_Function_Type;

std::string Duplicate_address_watcher::operator()(const Action action) {
        // TODO this does not work for ipv6
        if (ip.family == AF_INET6)
                return "";

        Main_Function_Type const main_function = ip.family == AF_INET ? daw_thread_main_ipv4 : daw_thread_main_ipv6;

        if (Action::add == action) {
                *loop = true;
                watcher = std::make_shared<std::thread>(main_function, iface, ip, std::ref(*loop), std::ref(pcap));
        }
        if (Action::del == action) {
                *loop = false;
                if (watcher != nullptr && watcher->joinable()) {
                        watcher->join();
                }
                watcher = nullptr;
        }
        return "";
}

