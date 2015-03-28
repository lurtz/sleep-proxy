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

#pragma once

#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include "ip_address.h"
#include "pcap_wrapper.h"
#include "scope_guard.h"

struct Duplicate_address_watcher {
        const std::string iface;
        const IP_address ip;
        Pcap_wrapper& pcap;
        std::shared_ptr<std::thread> watcher;
        std::shared_ptr<std::atomic_bool> loop;

        Duplicate_address_watcher(const std::string, const IP_address, Pcap_wrapper&);

        std::string operator()(const Action action);
};

