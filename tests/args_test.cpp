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
#include <cppunit/TestAssert.h>
#include <cppunit/extensions/HelperMacros.h>
#include <string>
#include <unistd.h>

namespace {

void compare(Host_args const &eargs, Host_args const &args) {
  CPPUNIT_ASSERT_EQUAL(eargs.interface, args.interface);
  CPPUNIT_ASSERT_EQUAL(eargs.address, args.address);
  CPPUNIT_ASSERT_EQUAL(eargs.ports, args.ports);
  CPPUNIT_ASSERT_EQUAL(eargs.mac, args.mac);
  CPPUNIT_ASSERT_EQUAL(eargs.hostname, args.hostname);
  CPPUNIT_ASSERT_EQUAL(eargs.ping_tries, args.ping_tries);
  CPPUNIT_ASSERT_EQUAL(eargs.wol_method, args.wol_method);
}

[[nodiscard]] std::vector<IP_address>
parse_ips(std::vector<std::string> const &addresses) {
  std::vector<IP_address> parsed_ips;
  parsed_ips.reserve(addresses.size());
  for (const auto &ip : addresses) {
    parsed_ips.push_back(parse_ip(ip));
  }
  return parsed_ips;
}

[[nodiscard]] std::vector<uint16_t>
parse_ports(std::vector<std::string> const &ports) {
  std::vector<uint16_t> ret_val(ports.size());
  std::transform(std::begin(ports), std::end(ports), std::begin(ret_val),
                 [](const std::string &s) { return std::stoi(s); });
  return ret_val;
}

[[nodiscard]] Args get_args(std::vector<std::string> &params) {
  // reset getopt() to the start
  optind = 0;
  auto vs = to_vector_strings(params);
  return read_commandline(static_cast<int>(params.size()),
                          get_c_string_array(vs).data());
}

[[nodiscard]] Args get_args_vec(bool const use_syslog) {
  std::vector<std::string> params{"args_test"};
  if (use_syslog) {
    std::cout << "syslog" << std::endl;
    params.emplace_back("--syslog");
  }
  return get_args(params);
}

[[nodiscard]] Args get_args(const std::string &filename,
                            const bool with_syslog = false) {
  std::vector<std::string> params{get_executable_path(), "-c",
                                  get_executable_directory() + "/" + filename};
  if (with_syslog) {
    params.insert(std::begin(params) + 1, "-s");
  }
  return get_args(params);
}

struct Input_args {
  std::string interface;
  std::vector<std::string> addresses;
  std::vector<std::string> ports;
  std::string mac;
  std::string hostname;
  std::string ping_tries;
  std::string wol_method;

  [[nodiscard]] Host_args to_args() const {
    return parse_host_args(interface, addresses, ports, mac, hostname,
                           ping_tries, wol_method);
  }

  [[nodiscard]] Host_args to_expected() const {
    return Host_args{interface,
                     parse_ips(addresses),
                     parse_ports(ports),
                     mac_to_binary(mac),
                     hostname,
                     static_cast<unsigned int>(std::stoul(ping_tries)),
                     parse_wol_method(wol_method)};
  }

  void compare() const { ::compare(to_expected(), to_args()); }
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
  CPPUNIT_TEST(test_ostream_operator_with_default_initialized_host_args);
  CPPUNIT_TEST(test_ostream_operator_with_value_initialized_host_args);
  CPPUNIT_TEST(test_ostream_operator_with_default_initialized_args);
  CPPUNIT_TEST(test_ostream_operator_with_empty_args_without_syslog);
  CPPUNIT_TEST(test_ostream_operator_with_empty_args_with_syslog);
  CPPUNIT_TEST(test_ostream_operator_with_initialized_args);
  CPPUNIT_TEST(test_read_command_line_weird_option);
  CPPUNIT_TEST_SUITE_END();

  Input_args input_args{
      "lo", {"fe80::123/64"}, {"12345"}, "1:12:34:45:67:89", {},
      "5",  "ethernet"};

public:
  void setUp() override { input_args.compare(); }

  void tearDown() override {}

  static void test_default_constructor() {
    Host_args args;

    CPPUNIT_ASSERT_EQUAL(ether_addr{{}}, args.mac);
    CPPUNIT_ASSERT_EQUAL(static_cast<unsigned int>(0), args.ping_tries);
    CPPUNIT_ASSERT_EQUAL(Wol_method::ethernet, args.wol_method);
  }

  void test_interface() {
    input_args.interface = "lo";
    input_args.compare();
    input_args.interface = "lo,eth0";
    CPPUNIT_ASSERT_THROW((void)input_args.to_args(), std::runtime_error);
    input_args.interface = "eth0;";
    CPPUNIT_ASSERT_THROW((void)input_args.to_args(), std::runtime_error);
  }

  void test_addresses() {
    input_args.addresses = std::vector<std::string>{"192.168.1.1"};
    Host_args args(input_args.to_args());
    input_args.addresses = std::vector<std::string>{"192.168.1.1/24"};
    ::compare(input_args.to_expected(), args);
    input_args.addresses = std::vector<std::string>{"::1"};
    Host_args args1(input_args.to_args());
    input_args.addresses = std::vector<std::string>{"::1/128"};
    ::compare(input_args.to_expected(), args1);
    input_args.addresses = std::vector<std::string>{"::1/128;"};
    CPPUNIT_ASSERT_THROW((void)input_args.to_args(), std::runtime_error);
    input_args.addresses = std::vector<std::string>{""};
    CPPUNIT_ASSERT_THROW((void)input_args.to_args(), std::invalid_argument);
    input_args.addresses = std::vector<std::string>{};
    CPPUNIT_ASSERT_THROW((void)input_args.to_args(), std::runtime_error);
  }

  void test_ports() {
    input_args.ports = std::vector<std::string>{"123"};
    input_args.compare();
    input_args.ports = std::vector<std::string>{"123456789"};
    CPPUNIT_ASSERT_THROW((void)input_args.to_args(), std::out_of_range);
    input_args.ports = std::vector<std::string>{"66000"};
    CPPUNIT_ASSERT_THROW((void)input_args.to_args(), std::out_of_range);
    input_args.ports = std::vector<std::string>{"12345;"};
    CPPUNIT_ASSERT_THROW((void)input_args.to_args(), std::invalid_argument);
    input_args.ports = std::vector<std::string>{"garbage"};
    CPPUNIT_ASSERT_THROW((void)input_args.to_args(), std::invalid_argument);
    input_args.ports = std::vector<std::string>{""};
    CPPUNIT_ASSERT_THROW((void)input_args.to_args(), std::invalid_argument);
    input_args.ports = std::vector<std::string>{};
    CPPUNIT_ASSERT_THROW((void)input_args.to_args(), std::runtime_error);
  }

  void test_mac() {
    input_args.mac = "aa:aa:aa:aa:bb:cc";
    Host_args args = input_args.to_args();
    ::compare(input_args.to_expected(), args);
    input_args.mac = "AA:AA:AA:AA:BB:CC";
    ::compare(input_args.to_expected(), args);
    input_args.mac = "01:2:03:04:05:06";
    Host_args args1 = input_args.to_args();
    input_args.mac = "1:2:3:4:5:6";
    ::compare(input_args.to_expected(), args1);
    input_args.mac = "";
    CPPUNIT_ASSERT_THROW((void)input_args.to_args(), std::runtime_error);
  }

  void test_hostname() {
    input_args.hostname = "asdf,.-";
    CPPUNIT_ASSERT_THROW((void)input_args.to_args(), std::runtime_error);
  }

  void test_ping_tries() {
    input_args.ping_tries = "1111111111111111111111";
    CPPUNIT_ASSERT_THROW((void)input_args.to_args(), std::out_of_range);
    input_args.ping_tries = "";
    CPPUNIT_ASSERT_THROW((void)input_args.to_args(), std::invalid_argument);
  }

  void test_wol_method() {
    input_args.wol_method = "unknown";
    CPPUNIT_ASSERT_THROW((void)input_args.to_args(), std::invalid_argument);
    input_args.wol_method = "";
    CPPUNIT_ASSERT_THROW((void)input_args.to_args(), std::invalid_argument);
  }

  static void test_syslog() {
    CPPUNIT_ASSERT(get_args_vec(true).syslog);
    CPPUNIT_ASSERT(!get_args_vec(false).syslog);
  }

  static void test_read_file() {
    auto args = get_args("watchhosts");
    CPPUNIT_ASSERT_EQUAL(static_cast<unsigned long>(3), args.host_args.size());

    Input_args const arg0{
        "lo",
        std::vector<std::string>{"10.0.0.1/16", "fe80::123/64"},
        std::vector<std::string>{"12345", "23456"},
        "1:12:34:45:67:89",
        "test.lan",
        "5",
        "ethernet"};
    ::compare(arg0.to_expected(), args.host_args.at(0));

    Input_args const arg1{
        "lo",
        std::vector<std::string>{"10.1.2.3/16", "fe80::de:ad/64"},
        std::vector<std::string>{"22"},
        "FF:EE:DD:CC:BB:AA",
        "test2",
        "1",
        "udp"};
    ::compare(arg1.to_expected(), args.host_args.at(1));

    Input_args const arg2{
        "lo",
        std::vector<std::string>{"10.0.0.1/16", "fe80::123/64"},
        std::vector<std::string>{"12345", "23456"},
        "1:12:34:45:67:89",
        "",
        "5",
        "ethernet"};
    ::compare(arg2.to_expected(), args.host_args.at(2));

    auto args2 = get_args("watchhosts-empty");
    CPPUNIT_ASSERT_EQUAL(static_cast<unsigned long>(0), args2.host_args.size());

    auto args3 = get_args("watchhosts", true);
    CPPUNIT_ASSERT(args3.syslog);
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

  static void test_ostream_operator_with_default_initialized_host_args() {
    std::stringstream ss;
    ss << Host_args{};
    CPPUNIT_ASSERT_EQUAL(
        std::string("Host_args(interface = , address = , ports = , mac = "
                    "0:0:0:0:0:0, hostname = , print_tries = 0, wol_method = "
                    "ethernet)"),
        ss.str());
  }

  void test_ostream_operator_with_value_initialized_host_args() {
    std::stringstream ss;
    ss << input_args.to_args();
    CPPUNIT_ASSERT_EQUAL(
        std::string(
            "Host_args(interface = lo, address = fe80::123/64, ports = 12345, "
            "mac = "
            "1:12:34:45:67:89, hostname = , print_tries = 5, wol_method = "
            "ethernet)"),
        ss.str());
  }

  static void test_ostream_operator_with_default_initialized_args() {
    std::stringstream ss;
    ss << Args{};
    CPPUNIT_ASSERT_EQUAL(std::string("Args(host_args = [], syslog = false)"),
                         ss.str());
  }

  static void test_ostream_operator_with_empty_args_without_syslog() {
    std::stringstream ss;
    ss << Args{{}, false};
    CPPUNIT_ASSERT_EQUAL(std::string("Args(host_args = [], syslog = false)"),
                         ss.str());
  }

  static void test_ostream_operator_with_empty_args_with_syslog() {
    std::stringstream ss;
    ss << Args{{}, true};
    CPPUNIT_ASSERT_EQUAL(std::string("Args(host_args = [], syslog = true)"),
                         ss.str());
  }

  void test_ostream_operator_with_initialized_args() {
    std::stringstream ss;
    ss << Args{{input_args.to_args()}, false};
    CPPUNIT_ASSERT_EQUAL(
        std::string(
            "Args(host_args = [Host_args(interface = lo, address = "
            "fe80::123/64, ports = 12345, "
            "mac = "
            "1:12:34:45:67:89, hostname = , print_tries = 5, wol_method = "
            "ethernet)], syslog = false)"),
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
      CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), args.host_args.size());

      cmd_args[1] = "-c";
      auto args1 = get_args(cmd_args);
      CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), args1.host_args.size());

      std::cout << std::flush;
    }

    auto const messages = std::get<0>(out_in).read();

    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(2), messages.size());

    CPPUNIT_ASSERT_EQUAL(std::string("got unknown option: f"), messages.at(0));
    CPPUNIT_ASSERT_EQUAL(std::string("got unknown option: c"), messages.at(1));
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(Args_test);

} // namespace
