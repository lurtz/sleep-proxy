#pragma once

#include <vector>
#include <sys/socket.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <linux/if.h>

/** C++ wrapper to socket functions */
struct Socket {
        private:
        /** socket fd */
        int sock;

        public:
        /** open a socket */
        Socket(int domain, int type, int protocol = 0);

        /** close the socket */
        ~Socket();

        /**
         * do not provide a copy constructor as it might leads to multiple
         * closing of one socket
         */
        Socket(const Socket&) = delete;

        /**
         * do not provide a copy constructor as it might leads to multiple
         * closing of one socket
         */
        Socket& operator=(const Socket&) = delete;

        /**
         * set socket option
         */
        template<typename Optval>
        void set_sock_opt(int level, int optname, Optval&& optval) {
                if (setsockopt(sock, level, optname, &optval, sizeof(Optval)) == -1) {
                        throw std::runtime_error(std::string("setsockopt() failed: ") + strerror(errno));
                }
        }

        /**
         * send buf to dest_addr
         */
        template<typename Sockaddr>
        ssize_t send_to(const std::vector<uint8_t>& buf, int flags, Sockaddr&& sockaddr) {
                ssize_t sent_bytes = sendto(sock, buf.data(), buf.size(), flags, reinterpret_cast<const struct sockaddr *>(&sockaddr), sizeof(Sockaddr));
                if (sent_bytes == -1) {
                        throw std::runtime_error(std::string("sendto() failed: ") + strerror(errno));
                }
                return sent_bytes;
        }

        void ioctl(const unsigned long, ifreq&) const;
        int get_ifindex(const std::string& iface) const;
        std::vector<uint8_t> get_hwaddr(const std::string&) const;
};

