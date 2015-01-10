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

File_descriptor::File_descriptor(const int fdd) : fd(fdd) {
        if (fdd < 0) {
                throw std::runtime_error(std::string("file descriptor is negative: ") + strerror(errno));
        }
}

File_descriptor::File_descriptor(File_descriptor&& rhs) : fd(-1), closed{true} {
        *this = std::move(rhs);
}

File_descriptor& File_descriptor::operator=(File_descriptor&& rhs) {
        std::swap(fd, rhs.fd);
        std::swap(closed, rhs.closed);
        return *this;
}

File_descriptor::~File_descriptor() {
        close();
}

File_descriptor::operator int() const {
        return fd;
}

void File_descriptor::close() {
        if (!closed) {
                if (::close(fd) == -1) {
                        throw std::runtime_error(std::string("pipe close() failed: ") + strerror(errno));
                }
        }
        closed = true;
}

