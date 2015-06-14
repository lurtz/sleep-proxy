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
#include <unistd.h>
#include <string>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <poll.h>
#include "container_utils.h"

File_descriptor::File_descriptor(char const *str)
    : File_descriptor(std::string(str)) {}

File_descriptor::File_descriptor(std::string name)
    : filename{std::move(name)}, delete_on_close{!file_exists(filename)} {
  if (!filename.empty()) {
    fd = open(filename.c_str(), O_CREAT | O_RDWR,
              S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (-1 == fd) {
      throw std::runtime_error(std::string("File_descriptor::open() failed: ") +
                               strerror(errno));
    }
  } else {
    fd = -1;
    delete_on_close = false;
  }
}

File_descriptor::File_descriptor(const int fdd, std::string name,
                                 bool delete_on_closee)
    : fd(fdd), filename(std::move(name)), delete_on_close(delete_on_closee) {
  if (fdd < 0) {
    throw std::runtime_error(std::string("file descriptor is negative: ") +
                             strerror(errno));
  }
}

File_descriptor::File_descriptor(File_descriptor &&rhs) : fd(-1), filename{""} {
  *this = std::move(rhs);
}

File_descriptor &File_descriptor::operator=(File_descriptor &&rhs) {
  std::swap(fd, rhs.fd);
  std::swap(filename, rhs.filename);
  std::swap(delete_on_close, rhs.delete_on_close);
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

void unlink_with_exception(std::string const &filename) {
  int const status = unlink(filename.c_str());
  if (status) {
    throw std::runtime_error(std::string("unlinking file ") + filename +
                             " failed: " + strerror(errno));
  }
}

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
  if (delete_on_close) {
    unlink_with_exception(filename);
  }
}

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
  if (fflush(stream)) {
    throw std::runtime_error(std::string("could not flush file: ") +
                             strerror(errno));
  }
}

void File_descriptor::remap(FILE *const stream) const {
  if (fd < 0) {
    return;
  }
  flush_file(stream);
  int const old_fd = get_fd_from_stream(stream);
  duplicate_file_descriptors(fd, old_fd);
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
  File_descriptor p0{pipefds[0], "selfpipe0", false};
  File_descriptor p1{pipefds[1], "selfpipe1", false};
  if (close_on_exec) {
    if (fcntl(p1.fd, F_SETFD, fcntl(p1.fd, F_GETFD) | FD_CLOEXEC)) {
      throw std::runtime_error(std::string("fcntl() failed: ") +
                               strerror(errno));
    }
  }

  return std::make_tuple(std::move(p0), std::move(p1));
}

int get_fd_from_stream(FILE *const stream) {
  int const fd = fileno(stream);
  if (-1 == fd) {
    throw std::runtime_error(
        std::string("could not get file descriptor of file: ") +
        strerror(errno));
  }
  return fd;
}

int duplicate_file_descriptors(int const from, int const to) {
  int const status = dup2(from, to);
  if (-1 == status) {
    throw std::runtime_error(std::string("cannot duplicate file descriptor: ") +
                             strerror(errno));
  }
  return status;
}
