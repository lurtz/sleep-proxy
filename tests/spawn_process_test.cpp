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

#include "main.h"
#include <string>
#include <thread>
#include <unistd.h>
#include <string.h>
#include "packet_test_utils.h"

#include "spawn_process.h"

class Spawn_process_test : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(Spawn_process_test);
  CPPUNIT_TEST(test_wait_until_pid_exits);
  CPPUNIT_TEST(test_fork_exec);
  CPPUNIT_TEST(test_get_path);
  CPPUNIT_TEST(test_direct_output_to_self_pipes);
  CPPUNIT_TEST_SUITE_END();

public:
  void setUp() {}

  void tearDown() {}

  void test_wait_until_pid_exits() {
    pid_t pid = -1;
    CPPUNIT_ASSERT_THROW(wait_until_pid_exits(pid), std::runtime_error);
  }

  void test_without_exceptions() const {
    std::vector<std::string> const cmd{"/bin/echo", "pspawn_test()"};
    pid_t pid = spawn(cmd);
    uint8_t status = wait_until_pid_exits(pid);
    CPPUNIT_ASSERT_EQUAL(static_cast<uint8_t>(0), status);

    std::vector<std::string> const cmd3{"/bin/ping", "aa"};
    pid = spawn(cmd3);
    status = wait_until_pid_exits(pid);
    CPPUNIT_ASSERT(0 != status);

    std::vector<std::string> const cmd4{"/sbin/fdisk", "/dev/sda", "bla"};
    pid = spawn(cmd4);
    status = wait_until_pid_exits(pid);
    CPPUNIT_ASSERT(0 != status);

    std::vector<std::string> const cmd5{"/bin/ping6", "-c3", "localhost"};
    pid = spawn(cmd5);
    status = wait_until_pid_exits(pid);
    CPPUNIT_ASSERT_EQUAL(static_cast<uint8_t>(0), status);
  }

  void test_with_exceptions() const {
    std::vector<std::string> cmd1{"/bin/whereAmI", "pspawn_test()"};
    CPPUNIT_ASSERT_THROW(spawn(cmd1), std::runtime_error);

    std::vector<std::string> cmd2{"/sbin/fdisk", "/dev/sda"};
    CPPUNIT_ASSERT_THROW(spawn(cmd1), std::runtime_error);
  }

  void test_fork_exec() {
    test_without_exceptions();
    test_with_exceptions();
  }

  void test_get_path() {
    CPPUNIT_ASSERT_EQUAL(std::string("/sbin/ip"), get_path("ip"));
    CPPUNIT_ASSERT_EQUAL(std::string("/sbin/iptables"), get_path("iptables"));
    CPPUNIT_ASSERT_EQUAL(std::string("/bin/sh"), get_path("sh"));
    CPPUNIT_ASSERT_EQUAL(std::string("/usr/bin/make"), get_path("make"));
    CPPUNIT_ASSERT_THROW(get_path("i_do_not_exist_fdasfd"), std::runtime_error);
  }

  void test_direct_output_to_self_pipes() {
    auto const self_pipes = get_self_pipes(false);
    std::vector<std::string> const cmd{get_path("echo"), "blablabla12"};
    pid_t const pid = spawn(cmd, "/dev/null", std::get<1>(self_pipes));
    uint8_t const status = wait_until_pid_exits(pid);
    CPPUNIT_ASSERT_EQUAL(static_cast<uint8_t>(0), status);
    auto const content = std::get<0>(self_pipes).read();
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), content.size());
    CPPUNIT_ASSERT_EQUAL(std::string("blablabla12"), content.at(0));
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(Spawn_process_test);
