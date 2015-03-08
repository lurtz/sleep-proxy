// Copyright (C) 2015  Lutz Reinhardt
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
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include "file_descriptor.h"
#include "to_string.h"
#include "spawn_process.h"

class File_descriptor_test : public CppUnit::TestFixture {
        std::string const filename = "fdclosetestfile";

        CPPUNIT_TEST_SUITE( File_descriptor_test );
        CPPUNIT_TEST( test_fd_constructor );
        CPPUNIT_TEST( test_fd_copy_constructor );
        CPPUNIT_TEST( test_fd_destructor );
        CPPUNIT_TEST( test_fd_close );
        CPPUNIT_TEST( test_fd_delete_on_close );
        CPPUNIT_TEST( test_fd_delete_content );
        CPPUNIT_TEST( test_fd_get_content );
        CPPUNIT_TEST_SUITE_END();
        public:
        void setUp() {
                CPPUNIT_ASSERT(!file_exists(filename));
        }

        void tearDown() {
                if (file_exists(filename)) {
                        std::vector<std::string> cmd{get_path("rm"), filename};
                        CPPUNIT_ASSERT_EQUAL(static_cast<uint8_t>(0), wait_until_pid_exits(spawn(cmd)));
                }
                CPPUNIT_ASSERT(!file_exists(filename));
        }

        int open_file() const {
                return open(filename.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        }

        void test_fd_constructor() {
                CPPUNIT_ASSERT_THROW(File_descriptor(-1, ""), std::runtime_error);
        }

        void test_fd_copy_constructor() {
                File_descriptor fd(open_file(), filename);
                CPPUNIT_ASSERT(file_exists(filename));
                CPPUNIT_ASSERT(-1 != fcntl(fd, F_GETFD));

                File_descriptor const fd2(std::move(fd));
                CPPUNIT_ASSERT(-1 != fcntl(fd2, F_GETFD));
                CPPUNIT_ASSERT(-1 == fcntl(fd, F_GETFD));

                CPPUNIT_ASSERT_EQUAL(-1, fd.fd);
                CPPUNIT_ASSERT_EQUAL(std::string(), fd.filename);

                CPPUNIT_ASSERT(file_exists(filename));
        }

        void test_fd_destructor() {
                int const c_fd = open_file();
                CPPUNIT_ASSERT(-1 != fcntl(c_fd, F_GETFD));
                CPPUNIT_ASSERT(file_exists(filename));
                {
                        File_descriptor fd(c_fd, filename);
                        CPPUNIT_ASSERT(-1 != fcntl(fd, F_GETFD));
                        CPPUNIT_ASSERT_EQUAL(c_fd, static_cast<int>(fd));
                        CPPUNIT_ASSERT(file_exists(filename));
                }
                CPPUNIT_ASSERT(-1 == fcntl(c_fd, F_GETFD));
        }

        void test_fd_close() {
                File_descriptor fd(open_file(), filename);
                CPPUNIT_ASSERT(-1 != fcntl(fd, F_GETFD));
                fd.close();
                CPPUNIT_ASSERT_EQUAL(-1, fcntl(fd, F_GETFD));
        }

        void test_fd_delete_on_close() {
                File_descriptor fd(open_file(), filename, false);
                CPPUNIT_ASSERT(-1 != fcntl(fd, F_GETFD));
                fd.close();
                CPPUNIT_ASSERT_EQUAL(-1, fcntl(fd, F_GETFD));
                CPPUNIT_ASSERT(file_exists(filename));
        }

        void test_fd_delete_content() {
                File_descriptor const fd{get_tmp_file("test_fd_delete_contentXXXXXX")};

                {
                        CPPUNIT_ASSERT_EQUAL(static_cast<ssize_t>(8), write(fd, "testdata", 8));
                        std::ifstream ifs(fd.filename);
                        std::string line;
                        CPPUNIT_ASSERT(std::getline(ifs, line));
                        CPPUNIT_ASSERT_EQUAL(std::string("testdata"), line);
                }

                fd.delete_content();

                {
                        std::ifstream ifs(fd.filename);
                        std::string line;
                        CPPUNIT_ASSERT(!std::getline(ifs, line));
                }
        }

        void test_fd_get_content() {
                File_descriptor const fd{get_tmp_file("test_fd_get_contentXXXXXX")};
                CPPUNIT_ASSERT_EQUAL(static_cast<ssize_t>(8), write(fd, "testdata", 8));
                CPPUNIT_ASSERT_EQUAL(static_cast<ssize_t>(1), write(fd, "\n", 1));
                CPPUNIT_ASSERT_EQUAL(static_cast<ssize_t>(9), write(fd, "testdata2", 9));

                std::vector<std::string> lines = fd.get_content();

                CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(2), lines.size());
                CPPUNIT_ASSERT_EQUAL(std::string("testdata"), lines.at(0));
                CPPUNIT_ASSERT_EQUAL(std::string("testdata2"), lines.at(1));

                CPPUNIT_ASSERT_EQUAL(static_cast<ssize_t>(1), write(fd, "\n", 1));
                lines = fd.get_content();

                CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(2), lines.size());
                CPPUNIT_ASSERT_EQUAL(std::string("testdata"), lines.at(0));
                CPPUNIT_ASSERT_EQUAL(std::string("testdata2"), lines.at(1));
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( File_descriptor_test );

