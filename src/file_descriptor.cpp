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

File_descriptor::File_descriptor(const int fdd, std::string name, bool delete_on_closee) : fd(fdd), filename(std::move(name)), delete_on_close(delete_on_closee) {
        if (fdd < 0) {
                throw std::runtime_error(std::string("file descriptor is negative: ") + strerror(errno));
        }
}

File_descriptor::File_descriptor(File_descriptor&& rhs) : fd(-1), filename{""} {
        *this = std::move(rhs);
}

File_descriptor& File_descriptor::operator=(File_descriptor&& rhs) {
        std::swap(fd, rhs.fd);
        std::swap(filename, rhs.filename);
        std::swap(delete_on_close, rhs.delete_on_close);
        return *this;
}

File_descriptor::~File_descriptor() {
        try {
                close();
        }
        catch (std::exception const & e) {
                std::cerr << "File_descriptor::~File_descriptor(): caught exception: " << e.what() << std::endl;
        }
}

File_descriptor::operator int() const {
        return fd;
}

void unlink_with_exception(std::string const & filename) {
        int const status = unlink(filename.c_str());
        if (status) {
                throw std::runtime_error(std::string("unlinking file ") + filename + "failed: " + strerror(errno));
        }
}

void File_descriptor::close() {
        if (fd > -1) {
                int const status = ::close(fd);
                fd = -1;
                if (status == -1) {
                        throw std::runtime_error(std::string("File_descriptor::close() failed: ") + strerror(errno));
                }
                if (delete_on_close) {
                        unlink_with_exception(filename);
                }
        }
}

