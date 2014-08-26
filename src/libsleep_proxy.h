#pragma once

#include <string>
#include <exception>
#include "args.h"

class Duplicate_address_exception : public std::exception {
        std::string message;
        public:
        Duplicate_address_exception(const std::string&);
        virtual const char * what() const noexcept;
};

bool ping_and_wait(const std::string& iface, const std::string& ip, const unsigned int tries);
bool emulate_host(const Args& args);
void signal_handler(int);
