#pragma once

#include <string>
#include "args.h"

bool ping_and_wait(const std::string& iface, const std::string& ip, const unsigned int tries);
void emulate_host(const Args& args);
void signal_handler(int);
