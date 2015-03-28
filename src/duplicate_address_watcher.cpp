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

void daw_thread_main_non_root(const std::string & iface, const IP_address & ip, std::atomic_bool & loop, Pcap_wrapper & pc) {
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
                } else {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
        }
}

void daw_thread_main_ipv6(const std::string & iface, const IP_address & ip, std::atomic_bool& loop, Pcap_wrapper& pc) {
        // 1. block incoming duplicate address detection for ip using firewall
        // 2. while(loop)
        // 2.1 use 'ip neigh' to watch for neighbors with the same ip
        // 2.2 if someone uses ip
        // 2.2.1 loop = false
        // 2.2.2 pc.break_loop
        Scope_guard const bipv6ns{Block_ipv6_neighbor_solicitation{ip}};
        daw_thread_main_non_root(iface, ip, loop, pc);
}

Duplicate_address_watcher::Duplicate_address_watcher(const std::string ifacee, const IP_address ipp, Pcap_wrapper& pc) : iface(std::move(ifacee)), ip(std::move(ipp)), pcap(pc), loop(std::make_shared<std::atomic_bool>(false)) {
}

typedef std::function<void(const std::string &, const IP_address &, std::atomic_bool&, Pcap_wrapper&)> Main_Function_Type;

std::string Duplicate_address_watcher::operator()(const Action action) {
        // TODO this does not work for ipv6
        if (ip.family == AF_INET6)
                return "";

        Main_Function_Type const main_function = ip.family == AF_INET ? daw_thread_main_non_root : daw_thread_main_ipv6;

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

