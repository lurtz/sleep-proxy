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
#include <stdexcept>

uint8_t wait_until_pid_exits(const pid_t &pid) {
  int status;
  do {
    pid_t wpid = waitpid(pid, &status, 0);
    if (wpid == -1) {
      throw std::runtime_error(std::string("waitpid() failed: ") +
                               strerror(errno));
    }
  } while (!WIFEXITED(status) && !WIFSIGNALED(status));
  if (WIFSIGNALED(status)) {
    raise(WTERMSIG(status));
  }
  return WEXITSTATUS(status);
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

void flush_file(FILE *const stream) {
  if (fflush(stream)) {
    throw std::runtime_error(std::string("could not flush file: ") +
                             strerror(errno));
  }
}

int duplicate_file_descriptors(int const from, int const to) {
  int const status = dup2(from, to);
  if (-1 == status) {
    throw std::runtime_error(std::string("cannot duplicate file descriptor: ") +
                             strerror(errno));
  }
  return status;
}

void remap_file_descriptor(File_descriptor const &fd, FILE *const stream) {
  if (fd < 0) {
    return;
  }
  flush_file(stream);
  int const old_fd = get_fd_from_stream(stream);
  duplicate_file_descriptors(fd, old_fd);
}

pid_t fork_exec_pipes(const std::vector<const char *> &command,
                      File_descriptor const &in, File_descriptor const &out) {
  std::tuple<File_descriptor, File_descriptor> pipes = get_self_pipes();

  pid_t child = fork();
  switch (child) {
  case -1:
    throw std::runtime_error(std::string("fork() failed with error: ") +
                             strerror(errno));
  case 0:
    // child
    remap_file_descriptor(in, stdin);
    remap_file_descriptor(out, stdout);
    std::get<0>(pipes).close();
    execv(command.at(0), const_cast<char **>(command.data()));
    write(std::get<1>(pipes), &errno, sizeof(int));
    _exit(0);
  default: {
    // parent
    std::get<1>(pipes).close();
    ssize_t count;
    int err;
    while ((count = read(std::get<0>(pipes), &err, sizeof(err))) == -1 &&
           (errno == EAGAIN || errno == EINTR))
      ;
    std::get<0>(pipes).close();
    if (count) {
      // something bad happend in the child process
      throw std::runtime_error(std::string("execv() failed: ") + strerror(err));
    }
  }
  }
  return child;
}

const std::array<std::string, 4> paths{
    {"/sbin", "/usr/sbin", "/bin", "/usr/bin"}};

std::string get_path(const std::string command) {
  for (const auto &p : paths) {
    const std::string fn = p + '/' + command;
    if (file_exists(fn))
      return fn;
  }
  throw std::runtime_error("unable to find path for file: " + command);
  return "";
}
