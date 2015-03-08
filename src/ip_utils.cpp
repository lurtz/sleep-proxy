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

#include "ip_utils.h"
#include "container_utils.h"
#include <sys/socket.h>
#include <stdexcept>
#include "int_utils.h"
#include "to_string.h"

std::string validate_iface(const std::string iface) {
        test_characters(iface, iface_chars, "iface contains invalid characters: " + iface);
        return iface;
}

static const std::string hex_chars{":0123456789abcdef"};

std::string validate_mac(std::string mac) {
        std::transform(std::begin(mac), std::end(mac), std::begin(mac), [](char ch) {return std::tolower(ch);});
        test_characters(mac, hex_chars, "mac address has to be given in hex");
        std::vector<std::string> items = split(mac, ':');
        if (items.size() != 6) {
                throw std::runtime_error("mac address is not 48 bit long: " + mac);
        }
        const bool b = std::all_of(std::begin(items), std::end(items), [] (std::string& item) { return item.size() == 2; });
        if (!b) {
                throw std::runtime_error("at start, end and between double colons of mac two digits have to be given");
        }
        return mac;
}

