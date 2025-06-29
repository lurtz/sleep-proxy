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

#include "args.h"
#include "error_suppression.h"
#include "libsleep_proxy.h"
#include "log.h"
#include <algorithm>
#include <csignal>
#include <cstdlib>
#include <future>
#include <span>
#include <thread>

namespace {
template <typename Container>
bool ping_ips(const std::string &iface, const Container &ips) {
  std::vector<std::future<bool>> futures;
  futures.reserve(ips.size());
  for (const auto &ip : ips) {
    futures.emplace_back(std::async(ping_and_wait, iface, ip, 1));
  }
  return std::any_of(std::begin(futures), std::end(futures),
                     [](std::future<bool> &f) { return f.get(); });
}

void thread_main(const Host_args &args) {
  bool loop = true;
  while (!is_signaled() && loop) {
    log_string(LOG_INFO, "ping " + args.hostname);
    while (ping_ips(args.interface, args.address) && !is_signaled()) {
      static auto const sleep_time = std::chrono::milliseconds(500);
      std::this_thread::sleep_for(sleep_time);
    }
    if (is_signaled()) {
      return;
    }
    try {
      Emulate_host_status const status = emulate_host(args);
      loop = Emulate_host_status::duplicate_address == status ||
             Emulate_host_status::success == status;
    } catch (const std::exception &e) {
      log(LOG_ERR, "caught exception what(): %s", e.what());
      raise(SIGTERM);
    } catch (...) {
      log_string(LOG_ERR,
                 "Something went terribly wrong at: " + to_string(args));
      raise(SIGTERM);
    }
  }
  log_string(LOG_INFO, "finished watching " + args.hostname);
}
} // namespace

int main(int argc, char *argv[]) {
  try {
    setup_signals();
    IGNORE_CLANG_WARNING
    std::span<char *> const args{argv, static_cast<size_t>(argc)};
    REENABLE_CLANG_WARNING
    auto argss = read_commandline(args);
    if (argss.host_args.empty()) {
      log_string(LOG_ERR, "no configuration given");
      return EXIT_FAILURE;
    }
    if (argss.syslog) {
      setup_log(args[0], 0, LOG_DAEMON);
    }
    std::vector<std::jthread> threads;
    threads.reserve(argss.host_args.size());
    for (auto const &hargs : argss.host_args) {
      threads.emplace_back(thread_main, hargs);
    }
  } catch (std::exception const &e) {
    log(LOG_ERR, "something wrong: %s\n", e.what());
  }
  return EXIT_SUCCESS;
}
