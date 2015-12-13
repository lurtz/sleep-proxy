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
#include <fstream>
#include "log.h"
#include "ip_utils.h"
#include "int_utils.h"
#include "ethernet.h"
#include <getopt.h>
#include <stdexcept>

bool to_syslog = false;

void reset() { to_syslog = false; }

Args::Args()
    : interface{}, address{}, ports{}, mac{{0}}, hostname{}, ping_tries{0},
      syslog(to_syslog) {}

Args::Args(const std::string interface_,
           const std::vector<std::string> addresss_,
           const std::vector<std::string> ports_, const std::string mac_,
           const std::string hostname_, const std::string ping_tries_)
    : interface(validate_iface(std::move(interface_))),
      address(parse_items(std::move(addresss_), parse_ip)),
      ports(parse_items(std::move(ports_), str_to_integral<uint16_t>)),
      mac(mac_to_binary(std::move(mac_))),
      hostname(test_characters(hostname_, iface_chars + "-",
                               "invalid token in hostname: " + hostname_)),
      ping_tries(str_to_integral<unsigned int>(ping_tries_)),
      syslog(to_syslog) {
  if (address.size() == 0) {
    throw std::runtime_error("no ip address given");
  }
  if (ports.size() == 0) {
    throw std::runtime_error("no port given");
  }
}

const std::string def_iface = "lo";
const std::string def_address_ipv4 = "10.0.0.1/16";
const std::string def_address_ipv6 = "fe80::123/64";
const std::string def_ports0 = "12345";
const std::string def_ports1 = "23456";
const std::string def_mac = "01:12:34:45:67:89";
const std::string def_hostname = "";
const std::string def_ping_tries = "5";

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

Args read_args(std::ifstream &file) {
  std::string interface = def_iface;
  std::vector<std::string> address;
  std::vector<std::string> ports;
  std::string mac = def_mac;
  std::string hostname = def_hostname;
  std::string ping_tries = def_ping_tries;
  std::string line;
  while (std::getline(file, line) && line.substr(0, 4) != "host") {
    if (line.size() == 0) {
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
  return Args(std::move(interface), std::move(address), std::move(ports),
              std::move(mac), std::move(hostname), std::move(ping_tries));
}

std::vector<Args> read_file(const std::string &filename) {
  std::ifstream file(filename);
  std::vector<Args> ret_val;
  std::string line;
  while (std::getline(file, line) && line.substr(0, 4) != "host") {
    ;
  }
  while (file) {
    ret_val.emplace_back(read_args(file));
  }
  return ret_val;
}

std::vector<Args> read_commandline(const int argc, char *const argv[]) {
  static const option long_options[] = {
      {"help", no_argument, nullptr, 'h'},
      {"config", required_argument, nullptr, 'c'},
      {"syslog", no_argument, nullptr, 's'},
      {nullptr, 0, nullptr, 0}};
  int option_index = 0;
  int c = -1;
  std::vector<Args> ret_val;
  // read cmd line arguments and checks them
  while ((c = getopt_long(argc, argv, "hc:s", long_options, &option_index)) !=
         -1) {
    switch (c) {
    case 'h':
      print_help();
      exit(0);
      break;
    case 'c':
      ret_val = read_file(optarg);
      break;
    case 's':
      to_syslog = true;
    case '?':
      log_string(LOG_ERR, std::string("got unknown option: ") +
                              static_cast<char>(optopt));
      break;
    default:
      log(LOG_ERR, "got weird option: %c", c);
      break;
    }
  }
  return ret_val;
}

std::ostream &operator<<(std::ostream &out, const Args &args) {
  out << "Args(interface = " << args.interface << ", address = " << args.address
      << ", ports = " << args.ports << ", mac = " << binary_to_mac(args.mac)
      << ", hostname = " << args.hostname
      << ", print_tries = " << args.ping_tries << ", syslog = " << args.syslog
      << ")";
  return out;
}
