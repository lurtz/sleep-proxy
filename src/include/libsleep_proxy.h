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

#include "args.h"
#include "ip_address.h"
#include <cstdint>
#include <exception>
#include <string>

void setup_signals();

[[nodiscard]] bool is_signaled();

void reset_signaled();

[[nodiscard]] std::string get_bindable_ip(const std::string &iface,
                                          const std::string &ip);

[[nodiscard]] std::string
rule_to_listen_on_ips_and_ports(const std::vector<IP_address> &ips,
                                const std::vector<uint16_t> &ports);

[[nodiscard]] bool ping_and_wait(const std::string &iface, const IP_address &ip,
                                 unsigned int tries);

enum class Emulate_host_status {
  success,
  wake_failure,
  signal_received,
  duplicate_address,
  undefined_error
};

Emulate_host_status emulate_host(const Host_args &args);
