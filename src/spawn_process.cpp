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

std::tuple<File_descriptor, File_descriptor> get_self_pipes() {
        int pipefds[2];
        if (pipe(pipefds)) {
                throw std::runtime_error(std::string("pipe() failed: ") + strerror(errno));
        }
        File_descriptor p0{pipefds[0]}, p1{pipefds[1]};
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

pid_t fork_exec_pipes(const std::vector<const char *>& command, const std::string& in, const std::string& out) {
        std::tuple<File_descriptor, File_descriptor> pipes = get_self_pipes();

        pid_t child = fork();
        switch (child) {
                case -1:
                        throw std::runtime_error(std::string("fork() failed with error: ") + strerror(errno));
                case 0:
                        // child
                        freopen_with_exception(in, "a", stdin);
                        freopen_with_exception(out, "a", stdout);
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

