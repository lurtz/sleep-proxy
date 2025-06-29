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

#include "args.h"
#include "ethernet.h"
#include "int_utils.h"
#include "ip_utils.h"
#include "log.h"
#include "wol.h"
#include <fstream>
#include <getopt.h>
#include <ios>
#include <stdexcept>

namespace {
const std::string def_iface = "lo";
const std::string def_address_ipv4 = "10.0.0.1/16";
const std::string def_address_ipv6 = "fe80::123/64";
const std::string def_ports0 = "12345";
const std::string def_ports1 = "23456";
const std::string def_mac = "01:12:34:45:67:89";
const std::string def_hostname;
const std::string def_ping_tries = "5";
const std::string def_wol_method = "ethernet";

Host_args read_args(std::ifstream &file) {
  std::string interface = def_iface;
  std::vector<std::string> address;
  std::vector<std::string> ports;
  std::string mac = def_mac;
  std::string hostname = def_hostname;
  std::string ping_tries = def_ping_tries;
  std::string wol_method = def_wol_method;
  std::string line;
  while (std::getline(file, line) && line.substr(0, 4) != "host") {
    if (line.empty()) {
      continue;
    }
    const auto token = split(line, ' ');
    if (token.size() != 2) {
      log_string(LOG_INFO, "skipping line \"" + line + "\"");
      log_string(LOG_INFO,
                 "needs to be a pair of name and value separated by space");
      continue;
    }
    if (token.at(0) == "interface") {
      interface = token.at(1);
    } else if (token.at(0) == "address") {
      address.push_back(token.at(1));
    } else if (token.at(0) == "port") {
      ports.push_back(token.at(1));
    } else if (token.at(0) == "mac") {
      mac = token.at(1);
    } else if (token.at(0) == "name") {
      hostname = token.at(1);
    } else if (token.at(0) == "ping_tries") {
      ping_tries = token.at(1);
    } else if (token.at(0) == "wol_method") {
      wol_method = token.at(1);
    } else {
      log_string(LOG_INFO, "unknown name \"" + token.at(0) + "\": skipping");
    }
  }
  if (address.empty()) {
    address.push_back(def_address_ipv4);
    address.push_back(def_address_ipv6);
  }
  if (ports.empty()) {
    ports.push_back(def_ports0);
    ports.push_back(def_ports1);
  }

  return parse_host_args(interface, address, ports, mac, hostname, ping_tries,
                         wol_method);
}

std::vector<Host_args> read_file(const std::string &filename) {
  std::ifstream file(filename);
  std::vector<Host_args> ret_val;
  std::string line;
  while (std::getline(file, line) && line.substr(0, 4) != "host") {
  }
  while (file) {
    ret_val.emplace_back(read_args(file));
  }
  return ret_val;
}
} // namespace

void print_help() {
  log_string(LOG_INFO, "usage: emulateHost [-h] [-s] [-c CONFIG]");
  log_string(LOG_INFO, "emulates a host, which went standby and wakes it upon "
                       "an incoming connection");
  log_string(LOG_INFO, "optional arguments:");
  log_string(LOG_INFO,
             "  -h, --help            show this help message and exit");
  log_string(LOG_INFO, "  -c CONFIG, --config CONFIG");
  log_string(
      LOG_INFO,
      "                        read config file, should be the last argument");
  log_string(LOG_INFO, "  -s, --syslog");
  log_string(LOG_INFO, "                        print messages to syslog");
}

Host_args parse_host_args(const std::string &interface_,
                          const std::vector<std::string> &addresss_,
                          const std::vector<std::string> &ports_,
                          const std::string &mac_, const std::string &hostname_,
                          const std::string &ping_tries_,
                          const std::string &wol_method_) {

  Host_args hargs(validate_iface(interface_), parse_items(addresss_, parse_ip),
                  parse_items(ports_, str_to_integral<uint16_t>),
                  mac_to_binary(mac_),
                  test_characters(hostname_, iface_chars + "-",
                                  "invalid token in hostname: " + hostname_),
                  str_to_integral<unsigned int>(ping_tries_),
                  parse_wol_method(wol_method_));
  if (hargs.address.empty()) {
    throw std::runtime_error("no ip address given");
  }
  if (hargs.ports.empty()) {
    throw std::runtime_error("no port given");
  }
  return hargs;
}

Args read_commandline(std::span<char *> const &args) {
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)
  static const option long_options[] = {
      {.name = "help", .has_arg = no_argument, .flag = nullptr, .val = 'h'},
      {.name = "config",
       .has_arg = required_argument,
       .flag = nullptr,
       .val = 'c'},
      {.name = "syslog", .has_arg = no_argument, .flag = nullptr, .val = 's'},
      {.name = nullptr, .has_arg = 0, .flag = nullptr, .val = 0}};
  int option_index = 0;
  int c = -1;
  std::vector<Host_args> ret_val;

  bool to_syslog = false;

  // read cmd line arguments and checks them
  while (
      (c = getopt_long(
           static_cast<int>(args.size()), args.data(), "hc:s",
           // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
           long_options, &option_index)) != -1) {
    switch (c) {
    case 'h':
      print_help();
      exit(0);
    case 'c':
      ret_val = read_file(optarg);
      break;
    case 's':
      to_syslog = true;
      break;
    case '?':
      log_string(LOG_ERR, std::string("got unknown option: ") +
                              static_cast<char>(optopt));
      break;
    default:
      log(LOG_ERR, "got weird option: %c", c);
      break;
    }
  }
  return {.host_args = std::move(ret_val), .syslog = to_syslog};
}

std::ostream &operator<<(std::ostream &out, const Host_args &args) {
  out << "Host_args(interface = " << args.interface << ", address = "
      << args.address << ", ports = " << args.ports
      << ", mac = " << binary_to_mac(args.mac)
      << ", hostname = " << args.hostname
      << ", print_tries = " << args.ping_tries
      << ", wol_method = " << args.wol_method << ")";
  return out;
}

std::ostream &operator<<(std::ostream &out, const Args &args) {
  out << "Args(host_args = [" << args.host_args
      << "], syslog = " << std::boolalpha << args.syslog << ")";
  return out;
}
