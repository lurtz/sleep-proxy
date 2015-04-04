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
#include "container_utils.h"

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
                             "failed: " + strerror(errno));
  }
}

void File_descriptor::close() {
  if (fd < 0) {
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

void File_descriptor::delete_content() const {
  auto const status = ftruncate(fd, 0);
  if (status < 0) {
    throw std::runtime_error(
        std::string("File_descriptor::delete_content() failed: ") +
        strerror(errno));
  }
}

off_t fseek_exception(int const fildes, off_t const offset, int const whence) {
  off_t const status = lseek(fildes, offset, whence);

  if (status == -1) {
    throw std::runtime_error(std::string("File_descriptor::fseek() failed: ") +
                             strerror(errno));
  }

  return status;
}

std::vector<uint8_t> pread_exception(int const fildes, size_t length,
                                     off_t const offset) {
  std::vector<uint8_t> data(length, 0);
  ssize_t read_bytes = pread(fildes, data.data(), data.size(), offset);

  if (read_bytes == -1) {
    throw std::runtime_error(std::string("File_descriptor::pread() failed: ") +
                             strerror(errno));
  }

  data.resize(static_cast<std::vector<uint8_t>::size_type>(read_bytes));
  return data;
}

std::vector<std::string> File_descriptor::get_content() const {
  off_t const current_pos = fseek_exception(fd, 0, SEEK_CUR);
  off_t const last_pos = fseek_exception(fd, 0, SEEK_END);
  fseek_exception(fd, current_pos, SEEK_SET);

  std::vector<uint8_t> const data =
      pread_exception(fd, static_cast<size_t>(last_pos), 0);
  std::vector<std::vector<uint8_t>> const splitted_data = split(data, '\n');

  std::vector<std::string> lines(splitted_data.size());
  std::transform(std::begin(splitted_data), std::end(splitted_data),
                 std::begin(lines), [](std::vector<uint8_t> const &v) {
    return std::string(std::begin(v), std::end(v));
  });
  return lines;
}

File_descriptor get_tmp_file(std::string const &filename) {
  std::string const path = std::string(P_tmpdir) + '/' + filename;
  std::vector<char> modifiable_string(path.size() + 1, '\0');
  std::copy(std::begin(path), std::end(path), std::begin(modifiable_string));

  int const raw_fd = mkstemp(modifiable_string.data());
  if (raw_fd == -1) {
    throw std::runtime_error(std::string("failed to create temporary file: ") +
                             strerror(errno));
  }

  return File_descriptor{raw_fd, modifiable_string.data()};
}
