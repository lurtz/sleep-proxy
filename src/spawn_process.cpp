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

#include "spawn_process.h"
#include <sys/wait.h>
#include <unistd.h>
#include <stdexcept>
#include <fcntl.h>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <tuple>
#include <sys/stat.h>
#include <stdexcept>

uint8_t wait_until_pid_exits(const pid_t& pid) {
        int status;
        do {
                pid_t wpid = waitpid(pid, &status, 0);
                if (wpid == -1) {
                        throw std::runtime_error(std::string("waitpid() failed: ") + strerror(errno));
                }
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
        if (WIFSIGNALED(status)) {
                raise(WTERMSIG(status));
        }
        return WEXITSTATUS(status);
}

IO_remap_params::IO_remap_params(char const * p) : type(PATH), path(p) {}

IO_remap_params::IO_remap_params(std::string p) : type(PATH), path(std::move(p)) {}

IO_remap_params::IO_remap_params(File_descriptor const & fd) : type(FILE_DESCRIPTOR), file_descriptor(&fd) {}

IO_remap_params::~IO_remap_params() {}

IO_remap_params& IO_remap_params::operator=(IO_remap_params&& rhs) {
        type = rhs.type;
        switch (type) {
                case PATH: path = std::move(rhs.path);
                           break;
                case FILE_DESCRIPTOR:
                           file_descriptor = std::move(rhs.file_descriptor);
                           break;
        }
        return *this;
}

IO_remap_params::Type IO_remap_params::get_type() const {
        return type;
}

std::string const & IO_remap_params::get_path() const {
        if (type != PATH) {
                throw std::runtime_error("requested path from IO_remap_params, but no path saved");
        }
        return path;
}

File_descriptor const & IO_remap_params::get_file_descriptor() const {
        if (type != FILE_DESCRIPTOR) {
                throw std::runtime_error("requested File_descriptor from IO_remap_params, but no File_descriptor saved");
        }
        if (nullptr == file_descriptor) {
                throw std::runtime_error("file descriptor is null");
        }
        return *file_descriptor;
}

std::tuple<File_descriptor, File_descriptor> get_self_pipes() {
        int pipefds[2];
        if (pipe(pipefds)) {
                throw std::runtime_error(std::string("pipe() failed: ") + strerror(errno));
        }
        File_descriptor p0{pipefds[0], "selfpipe0", false};
        File_descriptor p1{pipefds[1], "selfpipe1", false};
        if (fcntl(p1.fd, F_SETFD, fcntl(p1.fd, F_GETFD) | FD_CLOEXEC)) {
                throw std::runtime_error(std::string("fcntl() failed: ") + strerror(errno));
        }

        return std::make_tuple(std::move(p0), std::move(p1));
}

void freopen_with_exception(const std::string& path, const std::string& mode, FILE * stream) {
        if (path.empty())
                return;
        if (freopen(path.c_str(), mode.c_str(), stream) == nullptr) {
                throw std::runtime_error(std::string("freopen(" + path + ", " + mode + ", ...) failed: ") + strerror(errno));
        }
}

int get_fd_from_stream(FILE * const stream) {
        int const fd = fileno(stream);
        if (-1 == fd) {
                throw std::runtime_error(std::string("could not get file descriptor of file: ") + strerror(errno));
        }
        return fd;
}

void flush_file(FILE * const stream) {
        if (fflush(stream)) {
                throw std::runtime_error(std::string("could not flush file: ") + strerror(errno));
        }
}

int duplicate_file_descriptors(int const from, int const to) {
        int const status = dup2(from, to);
        if (-1 == status) {
                throw std::runtime_error(std::string("cannot duplicate file descriptor: ") + strerror(errno));
        }
        return status;
}

void remap_file_descriptor(File_descriptor const & fd, FILE * const stream) {
        flush_file(stream);
        int const old_fd = get_fd_from_stream(stream);
        duplicate_file_descriptors(fd, old_fd);
}

void io_remap(IO_remap_params const & params, std::string const & mode, FILE * const stream) {
        switch (params.get_type()) {
                case IO_remap_params::PATH:
                        freopen_with_exception(params.get_path(), mode, stream);
                        break;
                case IO_remap_params::FILE_DESCRIPTOR:
                        remap_file_descriptor(params.get_file_descriptor(), stream);
                        break;
        }
}

pid_t fork_exec_pipes(const std::vector<const char *>& command, IO_remap_params const & in, IO_remap_params const & out) {
        std::tuple<File_descriptor, File_descriptor> pipes = get_self_pipes();

        pid_t child = fork();
        switch (child) {
                case -1:
                        throw std::runtime_error(std::string("fork() failed with error: ") + strerror(errno));
                case 0:
                        // child
                        io_remap(in, "a", stdin);
                        io_remap(out, "a", stdout);
                        std::get<0>(pipes).close();
                        execv(command.at(0), const_cast<char **>(command.data()));
                        write(std::get<1>(pipes).fd, &errno, sizeof(int));
                        _exit(0);
                default: {
                        // parent
                        std::get<1>(pipes).close();
                        ssize_t count;
                        int err;
                        while ((count = read(std::get<0>(pipes).fd, &err, sizeof(err))) == -1 && (errno == EAGAIN || errno == EINTR));
                        std::get<0>(pipes).close();
                        if (count) {
                            // something bad happend in the child process
                            throw std::runtime_error(std::string("execv() failed: ") + strerror(err));
                        }
                     }
        }
        return child;
}

bool file_exists(const std::string& filename) {
        struct stat stats;
        const auto errno_save = errno;
        bool ret_val = stat(filename.c_str(), &stats) == 0;
        errno = errno_save;
        return ret_val;
}

const std::array<std::string, 4> paths{{"/sbin", "/usr/sbin", "/bin", "/usr/bin"}};

std::string get_path(const std::string command) {
        for (const auto& p : paths) {
                const std::string fn = p + '/' + command;
                if (file_exists(fn))
                        return fn;
        }
        throw std::runtime_error("unable to find path for file: " + command);
        return "";
}

