#include "socket.h"
#include <stdexcept>
#include <unistd.h>
#include <cstring>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include "to_string.h"

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

void Socket::ioctl(const unsigned long req_number, ifreq& ifr) const {
        if (::ioctl(sock, req_number, &ifr) == -1) {
                throw std::runtime_error(std::string("ioctl() failed with request ") + to_string(req_number) + ": " + strerror(errno));
        }
}

ifreq get_ifreq(const std::string& iface) {
        struct ifreq ifr{{{0}}, {{0, {0}}}};
        std::copy(std::begin(iface), std::end(iface), std::begin(ifr.ifr_name));
        return ifr;
}

int Socket::get_ifindex(const std::string& iface) const {
        struct ifreq ifr = get_ifreq(iface);
        ioctl(SIOCGIFINDEX, ifr);
        return ifr.ifr_ifindex;
}

std::vector<uint8_t> Socket::get_hwaddr(const std::string& iface) const {
        struct ifreq ifr = get_ifreq(iface);
        ioctl(SIOCGIFHWADDR, ifr);
        return std::vector<uint8_t>(ifr.ifr_hwaddr.sa_data, ifr.ifr_hwaddr.sa_data+ETH_ALEN);
}
