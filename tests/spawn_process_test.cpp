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

#include "spawn_process.h"

class Spawn_process_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Spawn_process_test );
        CPPUNIT_TEST( test_fork_exec );
        CPPUNIT_TEST_SUITE_END();
        public:
        void setUp() {}

        void tearDown() {}

        void test_without_exceptions() {
                std::vector<std::string> cmd{"/bin/echo", "pspawn_test()"};
                pid_t pid = spawn(cmd);
                uint8_t status = wait_until_pid_exits(pid);
                CPPUNIT_ASSERT_EQUAL(static_cast<uint8_t>(0), status);

                std::vector<std::string> cmd3{"/bin/ping", "aa"};
                pid = spawn(cmd3);
                status = wait_until_pid_exits(pid);
                CPPUNIT_ASSERT(0 != status);

                std::vector<std::string> cmd4{"/sbin/fdisk", "/dev/sda", "bla"};
                pid = spawn(cmd4);
                status = wait_until_pid_exits(pid);
                CPPUNIT_ASSERT(0 != status);

                std::vector<std::string> cmd5{"/bin/ping6", "-c3", "localhost"};
                pid = spawn(cmd5);
                status = wait_until_pid_exits(pid);
                CPPUNIT_ASSERT_EQUAL(static_cast<uint8_t>(0), status);
        }

        void test_with_exceptions() {
                std::vector<std::string> cmd1{"/bin/whereAmI", "pspawn_test()"};
                CPPUNIT_ASSERT_THROW(spawn(cmd1), std::runtime_error);

                std::vector<std::string> cmd2{"/sbin/fdisk", "/dev/sda"};
                CPPUNIT_ASSERT_THROW(spawn(cmd1), std::runtime_error);
        }

        void test_fork_exec() {
                test_without_exceptions();
                test_with_exceptions();
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Spawn_process_test );

