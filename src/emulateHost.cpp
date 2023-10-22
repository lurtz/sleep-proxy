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

#include "libsleep_proxy.h"
#include "log.h"
#include <cstdlib>
#include <span>

int main(int argc, char *argv[]) {
  std::span<char *> const args{argv, static_cast<size_t>(argc)};
  Args argss(read_commandline(args));
  if (argss.host_args.empty()) {
    log_string(LOG_ERR, "no configuration given");
    return EXIT_FAILURE;
  }
  if (argss.syslog) {
    setup_log(args[0], 0, LOG_DAEMON);
  }
  log_string(LOG_INFO, argss.host_args.at(0));
  setup_signals();
  try {
    emulate_host(argss.host_args.at(0));
  } catch (std::exception &e) {
    log(LOG_ERR, "what: %s", e.what());
  } catch (...) {
    log_string(LOG_ERR, "Something went terribly wrong");
  }
  return EXIT_FAILURE;
}
