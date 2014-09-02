#pragma once

#include <string>
#include <vector>
#include <ostream>

/**
 * Parses and checks the input of the command line arguments
 */
struct Args {
        /** the interface to use */
        const std::string interface;
        /** addresses to listen on */
        const std::vector<std::string> address;
        /** ports to listen on */
        const std::vector<uint16_t> ports;
        /** mac of the target machine to wake up */
        const std::string mac;
        const std::string hostname;
        const unsigned int ping_tries;
        const bool& syslog;

        Args();

        Args(const std::string interface_, const std::vector<std::string> addresss_, const std::vector<std::string> ports_, const std::string mac_, const std::string hostname_, const std::string ping_tries_);

        Args(const std::string interface_, const std::string addresss_, const std::string ports_, const std::string mac_, const std::string hostname_, const std::string ping_tries_);
};

std::vector<Args> read_commandline(const int argc, char * const argv[]);

/**
 * write args into out
 */
std::ostream& operator<<(std::ostream& out, const Args& args);

