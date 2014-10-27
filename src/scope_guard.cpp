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
#include <map>
#include <arpa/inet.h>
#include <cerrno>
#include "log.h"
#include "to_string.h"
#include "ip_utils.h"
#include "split.h"
#include "spawn_process.h"

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
        const static std::map<Action, std::string> which_action{{Action::add, "add"}, {Action::del, "del"}};
        const std::string saction{which_action.at(action)};
        return get_path("ip") + " addr " + saction + " " + ip.with_subnet() + " dev " + iface;
}

/**
 * ipv4 and ipv6 have different iptables commands. return the one matching
 * the version of ip
 */
std::string get_iptables_cmd(const IP_address& ip) {
        const static std::map<int, std::string> which_iptcmd{{AF_INET, "iptables"}, {AF_INET6, "ip6tables"}};
        return get_path(which_iptcmd.at(ip.family));
}

std::string iptables_action(const Action& action) {
        const static std::map<Action, std::string> which_action{{Action::add, "I"}, {Action::del, "D"}};
        return which_action.at(action);
}

std::string Drop_port::operator()(const Action action) const {
        const std::string saction{iptables_action(action)};
        const std::string iptcmd = get_iptables_cmd(ip);
        const std::string pip = ip.pure();
        return iptcmd + " -w -" + saction + " INPUT -d " + pip + " -p tcp --syn --dport " + to_string(port) + " -j DROP";
}

std::string Reject_tp::operator()(const Action action) const {
        const static std::map<TP, std::string> which_tp{{TP::TCP, "tcp"}, {TP::UDP, "udp"}};
        const std::string saction{iptables_action(action)};
        const std::string stp{which_tp.at(tcp_udp)};
        const std::string iptcmd = get_iptables_cmd(ip);
        const std::string pip = ip.pure();
        return iptcmd + " -w -" + saction + " INPUT -d " + pip + " -p " + stp + " -j REJECT";
}

/**
 * in iptables the icmp parameter is differenct for IPv4 and IPv6. return
 * the correct one according to the ip version
 */
std::string get_icmp_version(const IP_address& ip) {
        const static std::map<int, std::string> which_icmp{{AF_INET, "icmp"}, {AF_INET6, "icmpv6"}};
        return which_icmp.at(ip.family);
}

std::string Block_icmp::operator()(const Action action) const {
        const std::string saction{iptables_action(action)};
        const std::string iptcmd = get_iptables_cmd(ip);
        const std::string icmpv = get_icmp_version(ip);
        return iptcmd + " -w -" + saction + " OUTPUT -d " + ip.pure() + " -p " + icmpv + " --" + icmpv + "-type destination-unreachable -j DROP";
}

void daw_thread_main(const std::string iface, const IP_address ip, std::atomic_bool& loop, Pcap_wrapper& pc) {
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

Duplicate_address_watcher::Duplicate_address_watcher(const std::string ifacee, const IP_address ipp, Pcap_wrapper& pc) : iface(std::move(ifacee)), ip(std::move(ipp)), pcap(pc), loop(std::make_shared<std::atomic_bool>(false)) {
}

std::string Duplicate_address_watcher::operator()(const Action action) {
        // TODO this does not work for ipv6
        if (ip.family == AF_INET6)
                return "";
        if (Action::add == action) {
                *loop = true;
                watcher = std::make_shared<std::thread>(daw_thread_main, iface, ip, std::ref(*loop), std::ref(pcap));
        }
        if (Action::del == action) {
                *loop = false;
                if (watcher->joinable()) {
                        watcher->join();
                }
                watcher = nullptr;
        }
        return "";
}

