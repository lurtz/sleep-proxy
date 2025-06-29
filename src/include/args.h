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

#include "ip_address.h"
#include "wol.h"
#include <cstdint>
#include <netinet/ether.h>
#include <ostream>
#include <span>
#include <string>
#include <vector>

void print_help();

/**
 * Parses and checks the input of the command line arguments
 */
struct Host_args {
  /** the interface to use */
  std::string interface{};
  /** addresses to listen on */
  std::vector<IP_address> address{};
  /** ports to listen on */
  std::vector<uint16_t> ports{};
  /** mac of the target machine to wake up */
  ether_addr mac{};
  std::string hostname{};
  unsigned int ping_tries{};
  Wol_method wol_method{};

  Host_args() = default;

  Host_args(std::string interface_, std::vector<IP_address> address_,
            std::vector<uint16_t> ports_, ether_addr mac_,
            std::string hostname_, unsigned int ping_tries_,
            Wol_method wol_method_)
      : interface{std::move(interface_)}, address{std::move(address_)},
        ports{std::move(ports_)}, mac{mac_}, hostname{std::move(hostname_)},
        ping_tries{ping_tries_}, wol_method{wol_method_} {}
};

struct Args {
  const std::vector<Host_args> host_args;
  const bool syslog;
};

[[nodiscard]] Host_args
parse_host_args(const std::string &interface_,
                const std::vector<std::string> &addresss_,
                const std::vector<std::string> &ports_, const std::string &mac_,
                const std::string &hostname_, const std::string &ping_tries_,
                const std::string &wol_method_);

[[nodiscard]] Args read_commandline(std::span<char *> const &args);

/**
 * write args into out
 */
std::ostream &operator<<(std::ostream &out, const Host_args &args);

/**
 * write args into out
 */
std::ostream &operator<<(std::ostream &out, const Args &args);
