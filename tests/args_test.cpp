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
#include "ip_address.h"
#include "ip_utils.h"
#include "packet_test_utils.h"
#include "to_string.h"

#include <algorithm>
#include <cppunit/extensions/HelperMacros.h>
#include <string>
#include <unistd.h>

struct Expected_args {
  /** the interface to use */
  std::string interface;
  /** addresses to listen on */
  std::vector<IP_address> address;
  /** ports to listen on */
  std::vector<uint16_t> ports;
  /** mac of the target machine to wake up */
  ether_addr mac;
  std::string hostname;
  unsigned int ping_tries;
  Wol_method wol_method;
  bool syslog;
};

void compare(Expected_args const &eargs, Args const &args) {
  CPPUNIT_ASSERT_EQUAL(eargs.interface, args.interface);
  CPPUNIT_ASSERT_EQUAL(eargs.address, args.address);
  CPPUNIT_ASSERT_EQUAL(eargs.ports, args.ports);
  CPPUNIT_ASSERT_EQUAL(eargs.mac, args.mac);
  CPPUNIT_ASSERT_EQUAL(eargs.hostname, args.hostname);
  CPPUNIT_ASSERT_EQUAL(eargs.ping_tries, args.ping_tries);
  CPPUNIT_ASSERT_EQUAL(eargs.wol_method, args.wol_method);
  CPPUNIT_ASSERT_EQUAL(eargs.syslog, args.syslog);
}

struct Input_args {
  std::string interface;
  std::vector<std::string> addresses;
  std::vector<std::string> ports;
  std::string mac;
  std::string hostname;
  std::string ping_tries;
  std::string wol_method;
  bool use_syslog;

  [[nodiscard]] std::vector<IP_address> parse_ips() const {
    std::vector<IP_address> parsed_ips;
    parsed_ips.reserve(addresses.size());
    for (const auto &ip : addresses) {
      parsed_ips.push_back(parse_ip(ip));
    }
    return parsed_ips;
  }

  [[nodiscard]] std::vector<uint16_t> parse_ports() const {
    std::vector<uint16_t> ret_val(ports.size());
    std::transform(std::begin(ports), std::end(ports), std::begin(ret_val),
                   [](const std::string &s) { return std::stoi(s); });
    return ret_val;
  }

  [[nodiscard]] Expected_args to_expected() const {
    return Expected_args{interface,
                         parse_ips(),
                         parse_ports(),
                         mac_to_binary(mac),
                         hostname,
                         static_cast<unsigned int>(std::stoul(ping_tries)),
                         parse_wol_method(wol_method),
                         use_syslog};
  }
};

class Args_test : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(Args_test);
  CPPUNIT_TEST(test_default_constructor);
  CPPUNIT_TEST(test_interface);
  CPPUNIT_TEST(test_addresses);
  CPPUNIT_TEST(test_ports);
  CPPUNIT_TEST(test_mac);
  CPPUNIT_TEST(test_hostname);
  CPPUNIT_TEST(test_ping_tries);
  CPPUNIT_TEST(test_wol_method);
  CPPUNIT_TEST(test_syslog);
  CPPUNIT_TEST(test_read_file);
  CPPUNIT_TEST(test_print_help);
  CPPUNIT_TEST(test_ostream_operator_with_default_initialized_args);
  CPPUNIT_TEST(test_ostream_operator_with_value_initialized_args);
  CPPUNIT_TEST(test_read_command_line_weird_option);
  CPPUNIT_TEST_SUITE_END();

  Input_args input_args{
      "lo", {"fe80::123/64"}, {"12345"}, "1:12:34:45:67:89", {},
      "5",  "ethernet",       false};

  [[nodiscard]] static std::vector<Args>
  get_args(std::vector<std::string> &params) {
    // reset getopt() to the start
    optind = 0;
    auto vs = to_vector_strings(params);
    return read_commandline(static_cast<int>(params.size()),
                            get_c_string_array(vs).data());
  }

  [[nodiscard]] std::vector<Args> get_args_vec() const {
    std::vector<std::string> params{"args_test"};
    if (input_args.use_syslog) {
      std::cout << "syslog" << std::endl;
      params.emplace_back("--syslog");
    }
    return get_args(params);
  }

  [[nodiscard]] Args get_args() const {
    return {input_args.interface, input_args.addresses, input_args.ports,
            input_args.mac,       input_args.hostname,  input_args.ping_tries,
            input_args.wol_method};
  }

  [[nodiscard]] static std::vector<Args>
  get_args(const std::string &filename, const bool with_syslog = false) {
    std::vector<std::string> params{get_executable_path(), "-c",
                                    get_executable_directory() + "/" +
                                        filename};
    if (with_syslog) {
      params.insert(std::begin(params) + 1, "-s");
    }
    return get_args(params);
  }

  [[nodiscard]] std::vector<uint16_t> parse_ports() const {
    std::vector<uint16_t> ret_val(input_args.ports.size());
    std::transform(std::begin(input_args.ports), std::end(input_args.ports),
                   std::begin(ret_val),
                   [](const std::string &s) { return std::stoi(s); });
    return ret_val;
  }

  void compare(const Args &args) const {
    CPPUNIT_ASSERT_EQUAL(input_args.interface, args.interface);
    std::vector<IP_address> parsed_ips;
    parsed_ips.reserve(input_args.addresses.size());
    for (const auto &ip : input_args.addresses) {
      parsed_ips.push_back(parse_ip(ip));
    }
    CPPUNIT_ASSERT_EQUAL(parsed_ips, args.address);
    CPPUNIT_ASSERT_EQUAL(parse_ports(), args.ports);
    std::string lower_mac = input_args.mac;
    std::transform(std::begin(lower_mac), std::end(lower_mac),
                   std::begin(lower_mac),
                   [](int ch) { return std::tolower(ch); });
    CPPUNIT_ASSERT_EQUAL(lower_mac, binary_to_mac(args.mac));
    CPPUNIT_ASSERT_EQUAL(input_args.hostname, args.hostname);
    CPPUNIT_ASSERT_EQUAL(
        static_cast<unsigned int>(std::stoul(input_args.ping_tries)),
        args.ping_tries);
    CPPUNIT_ASSERT_EQUAL(parse_wol_method(input_args.wol_method),
                         args.wol_method);
    CPPUNIT_ASSERT_EQUAL(input_args.use_syslog, args.syslog);
  }

public:
  void setUp() override {
    reset();
    compare(get_args());
  }

  void tearDown() override {}

  static void test_default_constructor() {
    Args args;

    CPPUNIT_ASSERT_EQUAL(ether_addr{{0}}, args.mac);
    CPPUNIT_ASSERT_EQUAL(static_cast<unsigned int>(0), args.ping_tries);
    CPPUNIT_ASSERT_EQUAL(false, args.syslog);
  }

  void test_interface() {
    input_args.interface = "lo";
    compare(get_args());
    input_args.interface = "lo,eth0";
    CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
    input_args.interface = "eth0;";
    CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
  }

  void test_addresses() {
    input_args.addresses = std::vector<std::string>{"192.168.1.1"};
    Args args(get_args());
    input_args.addresses = std::vector<std::string>{"192.168.1.1/24"};
    compare(args);
    input_args.addresses = std::vector<std::string>{"::1"};
    Args args1(get_args());
    input_args.addresses = std::vector<std::string>{"::1/128"};
    compare(args1);
    input_args.addresses = std::vector<std::string>{"::1/128;"};
    CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
    input_args.addresses = std::vector<std::string>{""};
    CPPUNIT_ASSERT_THROW(get_args(), std::invalid_argument);
    input_args.addresses = std::vector<std::string>{};
    CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
  }

  void test_ports() {
    input_args.ports = std::vector<std::string>{"123"};
    compare(get_args());
    input_args.ports = std::vector<std::string>{"123456789"};
    CPPUNIT_ASSERT_THROW(get_args(), std::out_of_range);
    input_args.ports = std::vector<std::string>{"66000"};
    CPPUNIT_ASSERT_THROW(get_args(), std::out_of_range);
    input_args.ports = std::vector<std::string>{"12345;"};
    CPPUNIT_ASSERT_THROW(get_args(), std::invalid_argument);
    input_args.ports = std::vector<std::string>{"garbage"};
    CPPUNIT_ASSERT_THROW(get_args(), std::invalid_argument);
    input_args.ports = std::vector<std::string>{""};
    CPPUNIT_ASSERT_THROW(get_args(), std::invalid_argument);
    input_args.ports = std::vector<std::string>{};
    CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
  }

  void test_mac() {
    input_args.mac = "aa:aa:aa:aa:bb:cc";
    Args args = get_args();
    compare(args);
    input_args.mac = "AA:AA:AA:AA:BB:CC";
    compare(args);
    input_args.mac = "01:2:03:04:05:06";
    Args args1 = get_args();
    input_args.mac = "1:2:3:4:5:6";
    compare(args1);
    input_args.mac = "";
    CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
  }

  void test_hostname() {
    input_args.hostname = "asdf,.-";
    CPPUNIT_ASSERT_THROW(get_args(), std::runtime_error);
  }

  void test_ping_tries() {
    input_args.ping_tries = "1111111111111111111111";
    CPPUNIT_ASSERT_THROW(get_args(), std::out_of_range);
    input_args.ping_tries = "";
    CPPUNIT_ASSERT_THROW(get_args(), std::invalid_argument);
  }

  void test_wol_method() {
    input_args.wol_method = "unknown";
    CPPUNIT_ASSERT_THROW(get_args(), std::invalid_argument);
    input_args.wol_method = "";
    CPPUNIT_ASSERT_THROW(get_args(), std::invalid_argument);
  }

  void test_syslog() {
    CPPUNIT_ASSERT(!Args().syslog);
    input_args.use_syslog = true;
    auto args = get_args_vec();
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), args.size());
    CPPUNIT_ASSERT(Args().syslog);
    reset();
    CPPUNIT_ASSERT(!Args().syslog);
  }

  void test_read_file() {
    auto args = get_args("watchhosts");
    CPPUNIT_ASSERT_EQUAL(static_cast<unsigned long>(3), args.size());
    input_args.interface = "lo";
    input_args.addresses =
        std::vector<std::string>{"10.0.0.1/16", "fe80::123/64"};
    input_args.ports = std::vector<std::string>{"12345", "23456"};
    input_args.mac = "1:12:34:45:67:89";
    input_args.hostname = "test.lan";
    input_args.ping_tries = "5";
    input_args.wol_method = "ethernet";
    compare(args.at(0));

    input_args.interface = "lo";
    input_args.addresses =
        std::vector<std::string>{"10.1.2.3/16", "fe80::de:ad/64"};
    input_args.ports = std::vector<std::string>{"22"};
    input_args.mac = "FF:EE:DD:CC:BB:AA";
    input_args.hostname = "test2";
    input_args.ping_tries = "1";
    input_args.wol_method = "udp";
    compare(args.at(1));

    input_args.interface = "lo";
    input_args.addresses =
        std::vector<std::string>{"10.0.0.1/16", "fe80::123/64"};
    input_args.ports = std::vector<std::string>{"12345", "23456"};
    input_args.mac = "1:12:34:45:67:89";
    input_args.hostname = "";
    input_args.ping_tries = "5";
    input_args.wol_method = "ethernet";
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

  static void test_ostream_operator_with_default_initialized_args() {
    Args args;
    std::stringstream ss;
    ss << args;
    CPPUNIT_ASSERT_EQUAL(
        std::string("Args(interface = , address = , ports = , mac = "
                    "0:0:0:0:0:0, hostname = , print_tries = 0, wol_method = "
                    "ethernet, syslog = 0)"),
        ss.str());
  }

  void test_ostream_operator_with_value_initialized_args() {
    std::stringstream ss;
    ss << get_args();
    CPPUNIT_ASSERT_EQUAL(
        std::string(
            "Args(interface = lo, address = fe80::123/64, ports = 12345, mac = "
            "1:12:34:45:67:89, hostname = , print_tries = 5, wol_method = "
            "ethernet, syslog = 0)"),
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
