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
#include "split.h"
#include <sys/socket.h>
#include <arpa/inet.h>
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


std::string get_pure_ip(const std::string& ip) {
        std::string wosubnet = split(ip, '/').at(0);
        std::string woiface = split(wosubnet, '%').at(0);
        return woiface;
}

int getAF(const std::string& ip) {
        std::string pure_ip = get_pure_ip(ip);
        in6_addr ipv6;
        if (inet_pton(AF_INET, pure_ip.c_str(), &ipv6) == 1) {
                return AF_INET;
        }
        if (inet_pton(AF_INET6, pure_ip.c_str(), &ipv6) == 1) {
                return AF_INET6;
        }
        throw std::runtime_error("ip " + ip + " is not as IPv4 or IPv6 recognizeable");
        return -1;
}

static const std::string ip_chars{"0123456789.abcdefghijklmnopqrstuvwxyzABCDEF:/%"};

std::string sanitize_ip(const std::string& ip) {
        test_characters(ip, ip_chars, "ip contains invalid characters: " + ip);
        // one slash or no slash
        if (ip.find('/') != ip.rfind('/')) {
                throw std::invalid_argument("Too many / in IP");
        }
        // getAF() throws if inet_pton() can not understand the ip
        // e.g. when the ip is ill formatted
        const int version = getAF(ip);
        std::string sane_ip = split(ip, '%').at(0);
        // if no subnet size is given, append standard values
        if (sane_ip == get_pure_ip(sane_ip)) {
                std::string postfix{"/24"};
                if (version == AF_INET6) {
                        postfix = ip != "::1" ? "/64" : "/128";
                }
                sane_ip = sane_ip + postfix;
        }
        // check if the subnet size is in correct bounds
        const unsigned int maxsubnetlen = version == AF_INET ? 32 : 128;
        std::string subnet{split(sane_ip, '/').at(1)};
        uint8_t postfix = str_to_integral<uint8_t>(subnet);
        if (postfix > maxsubnetlen) {
                std::string ss = "Subnet " + subnet + " is not in range 0.." + to_string(maxsubnetlen);
                throw std::invalid_argument(ss);
        }
        return sane_ip;
}

