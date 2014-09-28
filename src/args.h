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
#include <vector>
#include <ostream>
#include <netinet/ether.h>
#include "ip_address.h"

/**
 * Parses and checks the input of the command line arguments
 */
struct Args {
        /** the interface to use */
        const std::string interface;
        /** addresses to listen on */
        const std::vector<IP_address> address;
        /** ports to listen on */
        const std::vector<uint16_t> ports;
        /** mac of the target machine to wake up */
        const ether_addr mac;
        const std::string hostname;
        const unsigned int ping_tries;
        const bool& syslog;

        Args();

        Args(const std::string interface_, const std::vector<std::string> addresss_, const std::vector<std::string> ports_, const std::string mac_, const std::string hostname_, const std::string ping_tries_);

        Args(const std::string interface_, const std::string addresss_, const std::string ports_, const std::string mac_, const std::string hostname_, const std::string ping_tries_);
};

std::vector<Args> read_commandline(const int argc, char * const argv[]);

/**
 * write args into out
 */
std::ostream& operator<<(std::ostream& out, const Args& args);

