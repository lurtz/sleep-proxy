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

#include "file_descriptor.h"
#include "container_utils.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {
auto const byte_vector_to_string = [](std::vector<uint8_t> const &v) {
  return std::string(std::begin(v), std::end(v));
};

std::vector<std::string>
byte_vector_to_strings(std::vector<uint8_t> const &data) {
  std::vector<std::vector<uint8_t>> const splitted_data = split(data, '\n');
  std::vector<std::string> lines(splitted_data.size());
  std::transform(std::begin(splitted_data), std::end(splitted_data),
                 std::begin(lines), byte_vector_to_string);
  return lines;
}

bool is_data_ready_to_read(int const fd) {
  pollfd fds{fd, POLLIN, 0};

  int retval = poll(&fds, 1, 0);

  if (-1 == retval) {
    throw std::runtime_error(std::string("File_descriptor::poll() failed: ") +
                             strerror(errno));
  }

  return retval != 0;
}
} // namespace

File_descriptor::File_descriptor() : fd(-1) {}

File_descriptor::File_descriptor(const int fdd) : fd(fdd) {
  if (fdd < 0) {
    throw std::runtime_error(std::string("file descriptor is negative: ") +
                             strerror(errno));
  }
}

File_descriptor::File_descriptor(File_descriptor &&rhs) noexcept : fd(-1) {
  *this = std::move(rhs);
}

File_descriptor &File_descriptor::operator=(File_descriptor &&rhs) noexcept {
  std::swap(fd, rhs.fd);
  return *this;
}

File_descriptor::~File_descriptor() {
  try {
    close();
  } catch (std::exception const &e) {
    std::cerr << "File_descriptor::~File_descriptor(): caught exception: "
              << e.what() << std::endl;
  }
}

File_descriptor::operator int() const { return fd; }

void File_descriptor::close() {
  if (fd < 0 || get_fd_from_stream(stdin) == fd ||
      get_fd_from_stream(stdout) == fd || get_fd_from_stream(stderr) == fd) {
    return;
  }

  int const status = ::close(fd);
  fd = -1;
  if (status == -1) {
    throw std::runtime_error(std::string("File_descriptor::close() failed: ") +
                             strerror(errno));
  }
}

std::vector<std::string> File_descriptor::read() const {
  std::vector<uint8_t> complete_data;

  ssize_t read_bytes{-1};
  while (is_data_ready_to_read(fd) && read_bytes != 0) {
    std::vector<uint8_t> data(100);
    read_bytes = ::read(fd, data.data(), data.size());
    if (read_bytes == -1) {
      throw std::runtime_error(std::string("File_descriptor::read() failed: ") +
                               strerror(errno));
    }
    data.resize(static_cast<size_t>(read_bytes));
    complete_data.insert(std::end(complete_data), std::begin(data),
                         std::end(data));
  }

  return byte_vector_to_strings(complete_data);
}

void flush_file(FILE *const stream) {
  if (nullptr == stream) {
    throw std::domain_error("given FILE input is nullptr");
  }
  if (fflush(stream)) {
    throw std::runtime_error(std::string("could not flush file: ") +
                             strerror(errno));
  }
}

bool file_exists(const std::string &filename) {
  struct stat stats;
  const auto errno_save = errno;
  bool ret_val = stat(filename.c_str(), &stats) == 0;
  errno = errno_save;
  return ret_val;
}

std::tuple<File_descriptor, File_descriptor>
get_self_pipes(bool const close_on_exec) {
  int pipefds[2];
  if (pipe(pipefds)) {
    throw std::runtime_error(std::string("pipe() failed: ") + strerror(errno));
  }
  File_descriptor p0{pipefds[0]};
  File_descriptor p1{pipefds[1]};
  if (close_on_exec) {
    if (fcntl(p1.fd, F_SETFD, fcntl(p1.fd, F_GETFD) | FD_CLOEXEC)) {
      throw std::runtime_error(std::string("fcntl() failed: ") +
                               strerror(errno));
    }
  }

  return std::make_tuple(std::move(p0), std::move(p1));
}

int get_fd_from_stream(FILE *const stream) {
  if (nullptr == stream) {
    throw std::domain_error("input FILE is nullptr");
  }
  int const fd = fileno(stream);
  if (-1 == fd) {
    throw std::runtime_error(
        std::string("could not get file descriptor of file: ") +
        strerror(errno));
  }
  return fd;
}
