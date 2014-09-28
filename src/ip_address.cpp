#include "ip_address.h"

std::string IP_address::pure() const {
        std::array<char, INET6_ADDRSTRLEN> text{{0}};
        inet_ntop(family, &address.ipv6, text.data(), text.size());
        return text.data();
}

std::ostream& operator<<(std::ostream& out, const IP_address& ipa) {
        out << ipa.pure() << "/" << ipa.subnet;
        return out;
}

