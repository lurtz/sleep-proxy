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

#pragma once

#include <type_traits>
#include <string>
#include <functional>
#include "to_string.h"
#include "file_descriptor.h"

uint8_t wait_until_pid_exits(const pid_t& pid);

struct IO_remap_params {
        enum Type {PATH, FILE_DESCRIPTOR};

        IO_remap_params(const char * p);

        IO_remap_params(std::string p);

        IO_remap_params(File_descriptor fd);

        IO_remap_params& operator=(IO_remap_params&& rhs);

        ~IO_remap_params();

        Type get_type() const;

        std::string const & get_path() const;

        File_descriptor const & get_file_descriptor() const;

        private:
        Type type;
        union { std::string path; File_descriptor file_descriptor; };
};

pid_t fork_exec_pipes(const std::vector<const char *>& command, IO_remap_params const & in, IO_remap_params const & out);

template<typename Container>
pid_t spawn(Container&& cmd, IO_remap_params const & in = IO_remap_params(""), IO_remap_params const & out = IO_remap_params("")) {
        static_assert(std::is_same<typename std::decay<Container>::type::value_type, std::string>::value, "container has to carry std::string");

        // get char * of each string
        std::vector<const char *> ch_ptr = get_c_string_array(cmd);

        return fork_exec_pipes(ch_ptr, in, out);
}

bool file_exists(const std::string& filename);

std::string get_path(const std::string command);

