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

#pragma once

#include <functional>
#include <algorithm>
#include <mutex>
#include <thread>
#include <atomic>
#include "pcap_wrapper.h"
#include "ip_address.h"

std::string get_path(const std::string command);

/** perform or reverse the modification */
enum struct Action {
        add,
        del
};

/**
 * Upon creation consume a resource or perform a modification. Upon deletion
 * reverse this modification.
 */
struct Scope_guard {
        private:
        /** if the consumed resource or modification is freed */
        bool freed;
        /** function to take or release */
        const std::function<std::string(const Action)> aquire_release;

        public:
        /**
         * Default constructor initializes anything with default values
         */
        Scope_guard();

        /**
         * consume the resource or perform modification using
         * aquire_release_arg
         */
        Scope_guard(std::function<std::string(const Action)>&& aquire_release_arg);

        /**
         * Move constructor
         */
        Scope_guard(Scope_guard&& rhs);

        ~Scope_guard();

        /**
         * Deleted to prevent freeing the same resource more than once
         */
        Scope_guard(const Scope_guard&) = delete;

        /**
         * Deleted to prevent freeing the same resource more than once
         */
        Scope_guard& operator=(const Scope_guard&) = delete;

        /**
         * Checks if the resource is already freed and frees them if not
         */
        void free();

        /**
         * Consume or free the resource
         */
        void take_action(const Action a) const;
};

/** Adds ip to iface, removes it afterwards */
struct Temp_ip {
        const std::string iface;
        const IP_address ip;

        std::string operator()(const Action action) const;
};

/** Adds a firewall rule to open port for ip */
struct Drop_port {
        const IP_address ip;
        const uint16_t port;

        std::string operator()(const Action action) const;
};

/** Adds a firewall rule to reject either TCP or UDP packets */
struct Reject_tp {
        enum struct TP {
                TCP,
                UDP
        };
        const IP_address ip;
        const TP tcp_udp;

        std::string operator()(const Action action) const;
};

/** Adds a firewall rule to block ICMP messages directed to ip */
struct Block_icmp {
        const IP_address ip;

        std::string operator()(const Action action) const;
};

template<typename Cont, typename T>
struct Ptr_guard {
        Cont& cont;
        std::mutex& cont_mutex;
        T& ref;

        std::string operator()(const Action action) {
                const std::lock_guard<std::mutex> lock(cont_mutex);
                switch (action) {
                        case Action::add: cont.emplace_back(&ref);
                                          break;
                        case Action::del: {
                                          const auto pos = std::find(std::begin(cont), std::end(cont), &ref);
                                          if (pos == std::end(cont)) {
                                                  throw std::runtime_error("element supposed to be managed by ptr_guard is gone missing from container");
                                          }
                                          cont.erase(pos);
                                          break;
                                          }
                        default: break;
                }
                return "";
        }
};

template<typename Cont, typename T>
Ptr_guard<Cont, T> ptr_guard(Cont& cont, std::mutex& cont_mutex, T& ref) {
        return Ptr_guard<Cont, T>{cont, cont_mutex, ref};
}

struct Duplicate_address_watcher {
        const std::string iface;
        const IP_address ip;
        Pcap_wrapper& pcap;
        std::shared_ptr<std::thread> watcher;
        std::shared_ptr<std::atomic_bool> loop;

        Duplicate_address_watcher(const std::string, const IP_address, Pcap_wrapper&);

        std::string operator()(const Action action);
};

