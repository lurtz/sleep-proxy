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

#include "to_string.h"
#include <stdexcept>
#include <vector>
#include <cerrno>
#include <cstring>

bool contains_only_valid_characters(const std::string& input, const std::string& valid_chars) {
        const bool b = std::all_of(std::begin(input), std::end(input), [&] (char ch) { return valid_chars.find(ch) != std::string::npos; });
        return b;
}

std::string test_characters(const std::string& input, const std::string& valid_chars, std::string error_message) {
        if (!contains_only_valid_characters(input, valid_chars)) {
                throw std::runtime_error(error_message);
        }
        return input;
}

File_descriptor get_tmp_file(std::string const & filename) {
        std::string const path = std::string(P_tmpdir) + '/' + filename;
        std::vector<char> modifiable_string(path.size() + 1, '\0');
        strncpy(modifiable_string.data(), path.c_str(), path.size());

        File_descriptor fd(mkstemp(modifiable_string.data()));

        if (errno != 0) {
                throw std::runtime_error(std::string("failed to create temporary file: ") + strerror(errno));
        }
        return fd;
}
