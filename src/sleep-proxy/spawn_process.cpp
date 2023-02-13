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
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <spawn.h>
#include <stdexcept>
#include <sys/wait.h>
#include <unistd.h>

uint8_t wait_until_pid_exits(const pid_t &pid) {
  int status = -1;
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
  return static_cast<uint8_t>(WEXITSTATUS(status));
}

struct File_actions {
  posix_spawn_file_actions_t fa{};

  File_actions() {
    auto const rc = posix_spawn_file_actions_init(&fa);
    if (0 != rc) {
      throw std::system_error{rc, std::system_category(),
                              "posix_spawn_file_actions_init()"};
    }
  }

  File_actions(File_actions const &) = delete;
  File_actions(File_actions &&) = delete;

  ~File_actions() { posix_spawn_file_actions_destroy(&fa); }

  File_actions &operator=(File_actions const &) = delete;
  File_actions &operator=(File_actions &&) = delete;

  void add_dup2(File_descriptor const &src, FILE *const dest) {
    if (src.fd < 0) {
      return;
    }
    auto const old_fd = get_fd_from_stream(dest);
    auto const rc = posix_spawn_file_actions_adddup2(&fa, src.fd, old_fd);
    if (0 != rc) {
      throw std::system_error{rc, std::system_category(),
                              "posix_spawn_file_actions_adddup2()"};
    }
  }
};

uint8_t spawn_wrapper(std::vector<char *> params, File_descriptor const &in,
                      File_descriptor const &out) {
  auto pid = pid_t{};
  auto const command = std::string{params.at(0)};
  File_actions file_actions{};
  file_actions.add_dup2(in, stdin);
  file_actions.add_dup2(out, stdout);

  auto const rc = posix_spawnp(&pid, command.data(), &file_actions.fa, nullptr,
                               params.data(), nullptr);
  if (0 != rc) {
    throw std::system_error{rc, std::system_category(),
                            "posix_spawn(" + command + ")"};
  }

  auto const exit_status = wait_until_pid_exits(pid);
  static auto const spawn_failure = uint8_t{127};
  if (spawn_failure == exit_status) {
    throw std::runtime_error{"failed to spawn process: " + command};
  }

  return exit_status;
}
