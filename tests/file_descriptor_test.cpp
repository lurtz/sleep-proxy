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
#include <string.h>

#include "file_descriptor.h"
#include "to_string.h"
#include "spawn_process.h"
#include <container_utils.h>
#include "packet_test_utils.h"

int duplicate_file_descriptors(int const from, int const to);
int get_fd_from_stream(FILE *const stream);

int dup_exception(int const fd) {
  auto const new_fd = dup(fd);
  if (new_fd == -1) {
    throw std::runtime_error(std::string() + strerror(errno));
  }
  return new_fd;
}

void write(File_descriptor const &fd, std::string const &text) {
  ssize_t const written_bytes = ::write(fd, text.c_str(), text.size());
  CPPUNIT_ASSERT(-1 != written_bytes);
  CPPUNIT_ASSERT_EQUAL(text.size(), static_cast<size_t>(written_bytes));
}

struct Tmp_fd_remap {
  int const m_previous_fd;
  int const m_to_fd;

  Tmp_fd_remap(int const from_fd, int const to_fd)
      : m_previous_fd{dup_exception(to_fd)}, m_to_fd{to_fd} {
    duplicate_file_descriptors(from_fd, m_to_fd);
  }

  ~Tmp_fd_remap() {
    try {
      duplicate_file_descriptors(m_previous_fd, m_to_fd);
    } catch (std::exception const &e) {
      std::cout << "Tmp_fd_remap::~Tmp_fd_remap() caught exception: "
                << e.what() << std::endl;
    }
  }
};

class File_descriptor_test : public CppUnit::TestFixture {
  std::string const filename = "fdclosetestfile";

  CPPUNIT_TEST_SUITE(File_descriptor_test);
  CPPUNIT_TEST(test_fd_constructor);
  CPPUNIT_TEST(test_fd_constructor_open);
  CPPUNIT_TEST(test_fd_copy_constructor);
  CPPUNIT_TEST(test_fd_destructor);
  CPPUNIT_TEST(test_file_exists);
  CPPUNIT_TEST(test_fd_close);
  CPPUNIT_TEST(test_fd_delete_on_close);
  CPPUNIT_TEST(test_fd_self_pipes_as_stdout);
  CPPUNIT_TEST(test_get_self_pipes);
  CPPUNIT_TEST(test_fd_read_file);
  CPPUNIT_TEST(test_fd_read_from_self_pipe);
  CPPUNIT_TEST(test_fd_self_pipe_without_close_on_exec);
  CPPUNIT_TEST_SUITE_END();

public:
  void setUp() { CPPUNIT_ASSERT(!file_exists(filename)); }

  void tearDown() {
    if (file_exists(filename)) {
      std::vector<std::string> cmd{get_path("rm"), filename};
      CPPUNIT_ASSERT_EQUAL(static_cast<uint8_t>(0),
                           wait_until_pid_exits(spawn(cmd)));
    }
    CPPUNIT_ASSERT(!file_exists(filename));
  }

  int open_file() const {
    return open(filename.c_str(), O_CREAT | O_RDWR,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  }

  void test_fd_constructor_open() {
    {
      File_descriptor fd("");
      CPPUNIT_ASSERT(0 > fd.fd);
      CPPUNIT_ASSERT(!fd.delete_on_close);
    }
    { File_descriptor fd("/dev/null"); }
    File_descriptor fd1(filename);
    std::ofstream ofs(filename);
    ofs << "blabla" << std::endl;
    auto const content = fd1.read();
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), content.size());
    CPPUNIT_ASSERT_EQUAL(std::string("blabla"), content.at(0));
  }

  void test_fd_constructor() {
    CPPUNIT_ASSERT_THROW(File_descriptor(-1, ""), std::runtime_error);
  }

  void test_fd_copy_constructor() {
    File_descriptor fd(filename);
    CPPUNIT_ASSERT(file_exists(filename));
    CPPUNIT_ASSERT(-1 != fcntl(fd, F_GETFD));

    File_descriptor const fd2(std::move(fd));
    CPPUNIT_ASSERT(-1 != fcntl(fd2, F_GETFD));
    CPPUNIT_ASSERT(-1 == fcntl(fd, F_GETFD));

    CPPUNIT_ASSERT_EQUAL(-1, fd.fd);
    CPPUNIT_ASSERT_EQUAL(std::string(), fd.filename);

    CPPUNIT_ASSERT(file_exists(filename));
  }

  void test_file_exists() {
    CPPUNIT_ASSERT(file_exists("/dev"));
    CPPUNIT_ASSERT(file_exists("/dev/null"));
    CPPUNIT_ASSERT(file_exists("/etc/fstab"));
    CPPUNIT_ASSERT(!file_exists("/dev/nullfdasfdsafdsafdsa"));
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
    File_descriptor fd(filename);
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

  void test_fd_self_pipes_as_stdout() {
    auto self_pipes = get_self_pipes();
    {
      Tmp_fd_remap const fd_remap{std::get<1>(self_pipes),
                                  get_fd_from_stream(stdout)};
      printf("blabla");
      std::cout << "rumsbums" << std::endl;
    }
    auto lines = std::get<0>(self_pipes).read();
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), lines.size());
    CPPUNIT_ASSERT_EQUAL(std::string("blablarumsbums"), lines.at(0));
  }

  void test_get_self_pipes() {
    auto self_pipes = get_self_pipes();
    write(std::get<1>(self_pipes), "testdata");
    write(std::get<1>(self_pipes), "\n");
    write(std::get<1>(self_pipes), "testdata2");
    write(std::get<1>(self_pipes), "testdata3");

    std::vector<std::string::value_type> data(100);
    ssize_t read_bytes =
        read(std::get<0>(self_pipes), data.data(), data.size());
    CPPUNIT_ASSERT(27 == read_bytes);
    data.resize(static_cast<size_t>(read_bytes));

    auto const lines = split(data, '\n');

    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(2), lines.size());
    CPPUNIT_ASSERT_EQUAL(
        std::string("testdata"),
        std::string(std::begin(lines.at(0)), std::end(lines.at(0))));
    CPPUNIT_ASSERT_EQUAL(
        std::string("testdata2testdata3"),
        std::string(std::begin(lines.at(1)), std::end(lines.at(1))));
  }

  void test_fd_read_file() {
    File_descriptor fd{get_tmp_file("test_fd_readXXXXXX")};

    {
      std::ofstream ifs(fd.filename);
      ifs << "blablabla" << std::endl;
      ifs << "blubblub" << std::endl;
    }

    std::vector<std::string> lines = fd.read();
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(2), lines.size());
    CPPUNIT_ASSERT_EQUAL(std::string("blablabla"), lines.at(0));
    CPPUNIT_ASSERT_EQUAL(std::string("blubblub"), lines.at(1));
  }

  void test_fd_read_from_self_pipe() {
    auto self_pipes = get_self_pipes();
    write(std::get<1>(self_pipes), "testdata");
    write(std::get<1>(self_pipes), "\n");
    write(std::get<1>(self_pipes), "testdata2");

    std::vector<std::string> data = std::get<0>(self_pipes).read();

    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(2), data.size());
    CPPUNIT_ASSERT_EQUAL(std::string("testdata"), data.at(0));
    CPPUNIT_ASSERT_EQUAL(std::string("testdata2"), data.at(1));
  }

  void test_fd_self_pipe_without_close_on_exec() {
    {
      auto const out_in = get_self_pipes();
      int const mode = fcntl(std::get<1>(out_in), F_GETFD);
      CPPUNIT_ASSERT(mode & FD_CLOEXEC);
    }
    {
      auto const out_in = get_self_pipes(false);
      int const mode = fcntl(std::get<1>(out_in), F_GETFD);
      CPPUNIT_ASSERT(!(mode & FD_CLOEXEC));
    }
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(File_descriptor_test);
