#pragma once

#include <arpa/inet.h>
#include <string>
#include <ostream>

struct IP_address {
        int family;
        union { in_addr ipv4; in6_addr ipv6; } address;
        uint8_t subnet;
        std::string pure() const;
};

std::ostream& operator<<(std::ostream& out, const IP_address& ipa);

