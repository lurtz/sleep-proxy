#include "socket.h"
#include <stdexcept>
#include <unistd.h>
#include <cstring>

Socket::Socket(int domain, int type, int protocol) : sock{socket(domain, type, protocol)} {
        if (sock < 0) {
                throw std::runtime_error(std::string("sock() failed with errno: ") + strerror(errno));
        }
}

Socket::~Socket() {
        if (close(sock) != 0) {
                throw std::runtime_error(std::string("close() failed with errno: ") + strerror(errno));
        }
}

