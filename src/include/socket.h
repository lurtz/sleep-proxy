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

#pragma once

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <linux/if.h>
#include <netinet/ether.h>
#include <stdexcept>
#include <sys/socket.h>
#include <vector>

/** C++ wrapper to socket functions */
class Socket {
  int sock;

protected:
  [[nodiscard]] int fd() const;

public:
  /** open a socket */
  Socket(int domain, int type, int protocol = 0);

  /** close the socket */
  ~Socket();

  /**
   * do not provide a copy constructor as it might lead to multiple
   * closing of one socket
   */
  Socket(const Socket &) = delete;

  Socket(Socket &&) = delete;

  /**
   * do not provide a copy constructor as it might lead to multiple
   * closing of one socket
   */
  Socket &operator=(const Socket &) = delete;

  Socket &operator=(Socket &&) = delete;

  /**
   * set socket option
   */
  template <typename Optval>
  void set_sock_opt(int level, int optname, Optval const &optval) {
    if (setsockopt(sock, level, optname, &optval, sizeof(Optval)) == -1) {
      throw std::runtime_error(std::string("setsockopt() failed: ") +
                               strerror(errno));
    }
  }

  /**
   * send buf to dest_addr
   */
  template <typename Sockaddr>
  ssize_t send_to(const std::vector<uint8_t> &buf, int flags,
                  Sockaddr const &sockaddr) {
    ssize_t sent_bytes = sendto(
        sock, buf.data(), buf.size(), flags,
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        reinterpret_cast<const struct sockaddr *>(&sockaddr), sizeof(Sockaddr));
    if (sent_bytes == -1) {
      throw std::runtime_error(std::string("sendto() failed: ") +
                               strerror(errno));
    }
    return sent_bytes;
  }

  void ioctl(unsigned long req_number, ifreq &ifr) const;

  [[nodiscard]] int get_ifindex(const std::string &iface) const;

  [[nodiscard]] ether_addr get_hwaddr(const std::string &iface) const;
};
