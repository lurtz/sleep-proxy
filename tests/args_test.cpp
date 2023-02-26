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
#include "ip_utils.h"
#include "packet_test_utils.h"
#include "to_string.h"

#include <algorithm>
#include <cppunit/extensions/HelperMacros.h>
#include <string>
#include <unistd.h>

class Args_test : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(Args_test);
  CPPUNIT_TEST(test_default_constructor);
  CPPUNIT_TEST(test_interface);
  CPPUNIT_TEST(test_addresses);
  CPPUNIT_TEST(test_ports);
  CPPUNIT_TEST(test_mac);
  CPPUNIT_TEST(test_hostname);
  CPPUNIT_TEST(test_ping_tries);
  CPPUNIT_TEST(test_syslog);
  CPPUNIT_TEST(test_read_file);
  CPPUNIT_TEST(test_print_help);
  CPPUNIT_TEST(test_ostream_operator);
  CPPUNIT_TEST(test_read_command_line_weird_option);
  CPPUNIT_TEST_SUITE_END();
  std::string interface = "lo";
  std::vector<std::string> addresses{"fe80::123/64"};
  std::vector<std::string> ports{"12345"};
  std::string mac = "1:12:34:45:67:89";
  std::string hostname;
  std::string ping_tries = "5";
  bool syslog__ = false;

public:
  void setUp() override {
    reset();
    compare(get_args());
  }

  static std::vector<Args> get_args(std::vector<std::string> &params) {
    // reset getopt() to the start
    optind = 0;
    auto vs = to_vector_strings(params);
    return read_commandline(static_cast<int>(params.size()),
                            get_c_string_array(vs).data());
  }

  std::vector<Args> get_args_vec() const {
    std::vector<std::string> params{"args_test"};
    if (syslog__) {
      std::cout << "syslog" << std::endl;
      params.emplace_back("--syslog");
    }
    return get_args(params);
  }

  Args get_args() const {
    return Args(interface, addresses, ports, mac, hostname, ping_tries);
  }

  static std::vector<Args> get_args(const std::string &filename,
                                    const bool with_syslog = false) {
    std::vector<std::string> params{get_executable_path(), "-c",
                                    get_executable_directory() + "/" +
                                        filename};
    if (with_syslog) {
      params.insert(std::begin(params) + 1, "-s");
    }
    return get_args(params);
  }

  std::vector<uint16_t> parse_ports() const {
    std::vector<uint16_t> ret_val(ports.size());
    std::transform(std::begin(ports), std::end(ports), std::begin(ret_val),
                   [](const std::string &s) { return std::stoi(s); });
    return ret_val;
  }

  void compare(const Args &args) const {
    CPPUNIT_ASSERT_EQUAL(interface, args.interface);
    std::vector<IP_address> parsed_ips;
    for (const auto &ip : addresses) {
      parsed_ips.push_back(parse_ip(ip));
    }
    CPPUNIT_ASSERT(parsed_ips == args.address);
    CPPUNIT_ASSERT(parse_ports() == args.ports);
    std::string lower_mac = mac;
    std::transform(std::begin(lower_mac), std::end(lower_mac),
                   std::begin(lower_mac),
                   [](int ch) { return std::tolower(ch); });
    CPPUNIT_ASSERT_EQUAL(lower_mac, binary_to_mac(args.mac));
    CPPUNIT_ASSERT_EQUAL(hostname, args.hostname);
    CPPUNIT_ASSERT_EQUAL(static_cast<unsigned int>(std::stoul(ping_tries)),
                         args.ping_tries);
    CPPUNIT_ASSERT_EQUAL(syslog__, args.syslog);
  }

  void tearDown() override {}

  static void test_default_constructor() {
    Args args;

    CPPUNIT_ASSERT_EQUAL(ether_addr{{0}}, args.mac);
    CPPUNIT_ASSERT_EQUAL(static_cast<unsigned int>(0), args.ping_tries);
    CPPUNIT_ASSERT_EQUAL(false, args.syslog);
  }

  void test_interface() {
    interface = "lo";
    compare(get_args());
    interface = "lo,eth0";
    CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
    interface = "eth0;";
    CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
  }

  void test_addresses() {
    addresses = std::vector<std::string>{"192.168.1.1"};
    Args args(get_args());
    addresses = std::vector<std::string>{"192.168.1.1/24"};
    compare(args);
    addresses = std::vector<std::string>{"::1"};
    Args args1(get_args());
    addresses = std::vector<std::string>{"::1/128"};
    compare(args1);
    addresses = std::vector<std::string>{"::1/128;"};
    CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
    addresses = std::vector<std::string>{""};
    CPPUNIT_ASSERT_THROW(get_args(), std::invalid_argument);
    addresses = std::vector<std::string>{};
    CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
  }

  void test_ports() {
    ports = std::vector<std::string>{"123"};
    compare(get_args());
    ports = std::vector<std::string>{"123456789"};
    CPPUNIT_ASSERT_THROW(get_args(), std::out_of_range);
    ports = std::vector<std::string>{"66000"};
    CPPUNIT_ASSERT_THROW(get_args(), std::out_of_range);
    ports = std::vector<std::string>{"12345;"};
    CPPUNIT_ASSERT_THROW(get_args(), std::invalid_argument);
    ports = std::vector<std::string>{"garbage"};
    CPPUNIT_ASSERT_THROW(get_args(), std::invalid_argument);
    ports = std::vector<std::string>{""};
    CPPUNIT_ASSERT_THROW(get_args(), std::invalid_argument);
    ports = std::vector<std::string>{};
    CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
  }

  void test_mac() {
    mac = "aa:aa:aa:aa:bb:cc";
    Args args = get_args();
    compare(args);
    mac = "AA:AA:AA:AA:BB:CC";
    compare(args);
    mac = "01:2:03:04:05:06";
    Args args1 = get_args();
    mac = "1:2:3:4:5:6";
    compare(args1);
    mac = "";
    CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
  }

  void test_hostname() {
    hostname = "asdf,.-";
    CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
  }

  void test_ping_tries() {
    ping_tries = "1111111111111111111111";
    CPPUNIT_ASSERT_THROW(get_args(), std::out_of_range);
    ping_tries = "";
    CPPUNIT_ASSERT_THROW(get_args(), std::invalid_argument);
  }

  void test_syslog() {
    CPPUNIT_ASSERT(!Args().syslog);
    syslog__ = true;
    auto args = get_args_vec();
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), args.size());
    CPPUNIT_ASSERT(Args().syslog);
    reset();
    CPPUNIT_ASSERT(!Args().syslog);
  }

  void test_read_file() {
    auto args = get_args("watchhosts");
    CPPUNIT_ASSERT_EQUAL(static_cast<unsigned long>(3), args.size());
    interface = "lo";
    addresses = std::vector<std::string>{"10.0.0.1/16", "fe80::123/64"};
    ports = std::vector<std::string>{"12345", "23456"};
    mac = "1:12:34:45:67:89";
    hostname = "test.lan";
    ping_tries = "5";
    compare(args.at(0));

    interface = "lo";
    addresses = std::vector<std::string>{"10.1.2.3/16", "fe80::de:ad/64"};
    ports = std::vector<std::string>{"22"};
    mac = "FF:EE:DD:CC:BB:AA";
    hostname = "test2";
    ping_tries = "1";
    compare(args.at(1));

    interface = "lo";
    addresses = std::vector<std::string>{"10.0.0.1/16", "fe80::123/64"};
    ports = std::vector<std::string>{"12345", "23456"};
    mac = "1:12:34:45:67:89";
    hostname = "";
    ping_tries = "5";
    compare(args.at(2));

    auto args2 = get_args("watchhosts-empty");
    CPPUNIT_ASSERT_EQUAL(static_cast<unsigned long>(0), args2.size());

    auto args3 = get_args("watchhosts", true);
    CPPUNIT_ASSERT_EQUAL(true, args3.at(0).syslog);
    CPPUNIT_ASSERT_EQUAL(true, args3.at(1).syslog);
  }

  static void test_print_help() {
    auto out_in = get_self_pipes();
    {
      Tmp_fd_remap const out_remap(std::get<1>(out_in),
                                   get_fd_from_stream(stdout));
      print_help();
      std::cout << std::flush;
    }
    auto const help_text = std::get<0>(out_in).read();
    CPPUNIT_ASSERT(help_text.size() > 7);
  }

  static void test_ostream_operator() {
    Args args;
    std::stringstream ss;
    ss << args;
    CPPUNIT_ASSERT_EQUAL(
        std::string("Args(interface = , address = , ports = , mac = "
                    "0:0:0:0:0:0, hostname = , print_tries = 0, syslog = 0)"),
        ss.str());
  }

  static void test_read_command_line_weird_option() {
    auto out_in = get_self_pipes();

    {
      std::cout << std::flush;
      Tmp_fd_remap const fd_remap{std::get<1>(out_in),
                                  get_fd_from_stream(stdout)};

      std::vector<std::string> cmd_args{"weird_option", "-f"};
      auto args = get_args(cmd_args);
      CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), args.size());

      cmd_args[1] = "-c";
      auto args1 = get_args(cmd_args);
      CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), args1.size());

      std::cout << std::flush;
    }

    auto const messages = std::get<0>(out_in).read();

    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(2), messages.size());

    CPPUNIT_ASSERT_EQUAL(std::string("got unknown option: f"), messages.at(0));
    CPPUNIT_ASSERT_EQUAL(std::string("got unknown option: c"), messages.at(1));
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(Args_test);
