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

#include <string>
#include <exception>
#include "args.h"
#include "ip_address.h"

void setup_signals();

bool is_signaled();

bool ping_and_wait(const std::string &iface, const IP_address &ip,
                   const unsigned int tries);

enum class Emulate_host_status {
  success,
  wake_failure,
  signal_received,
  duplicate_address,
  undefined_error
};

Emulate_host_status emulate_host(const Args &args);
