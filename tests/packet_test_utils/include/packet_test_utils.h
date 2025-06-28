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

#include <cppunit/extensions/HelperMacros.h>
#include <cstdint>
#include <ethernet.h>
#include <file_descriptor.h>
#include <ip.h>
#include <ip_address.h>
#include <memory>
#include <pcap_wrapper.h>
#include <spawn_process.h>
#include <to_string.h>
#include <tuple>
#include <vector>

std::vector<uint8_t> to_binary(const std::string &hex);

enum class Payload_protocol {
  ipv4 = ETHERTYPE_IP,
  ipv6 = ETHERTYPE_IPV6,
  vlan = ETHERTYPE_VLAN
};

void test_ll(const std::unique_ptr<Link_layer> &ll, size_t length,
             const std::string &src, Payload_protocol payload_protocol,
             const std::string &info);

void test_ip(const std::unique_ptr<ip> &ip, ip::Version v,
             const std::string &src, const std::string &dst,
             size_t header_length, ip::Payload pl_type);

bool operator==(const Link_layer &lhs, const Link_layer &rhs);

bool operator==(const ip &lhs, const ip &rhs);

bool operator<(IP_address const &lhs, IP_address const &rhs);

std::vector<std::string> get_ip_neigh_output();

using Iface_Ips = std::vector<std::tuple<std::string, IP_address>>;

Iface_Ips get_iface_ips(std::vector<std::string> const &ip_neigh_content);

template <typename Container0, typename Container1>
std::vector<std::tuple<typename Container0::value_type,
                       typename Container1::value_type>>
cartesian_product(Container0 const &c0, Container1 const &c1) {
  std::vector<std::tuple<typename Container0::value_type,
                         typename Container1::value_type>>
      retVal;
  for (auto const &c0item : c0) {
    for (auto const &c1item : c1) {
      retVal.emplace_back(std::make_tuple(c0item, c1item));
    }
  }
  return retVal;
}

template <typename Iterator, typename End_iter>
void check_range(Iterator &&iter, End_iter &&end, const unsigned char start,
                 const unsigned char end_pos) {
  for (unsigned char c = start; c < end_pos && iter != end; c++, iter++) {
    CPPUNIT_ASSERT_EQUAL(static_cast<uint8_t>(16 * c + c), *iter);
  }
}

template <typename Iterator, typename End_iter>
void check_header(Iterator &&iter, End_iter &&end, const unsigned char start,
                  const unsigned char end_pos) {
  check_range(iter, end, start, end_pos);
  CPPUNIT_ASSERT(iter != end);
}

int dup_exception(int fd);

void write(File_descriptor const &fd, std::string const &text);

int duplicate_file_descriptors(int from, int to);

struct Fd_restore {
  int const m_fd;
  int const m_backup_fd;
  explicit Fd_restore(int fd);
  Fd_restore(Fd_restore const &) = delete;
  Fd_restore(Fd_restore &&) = delete;

  ~Fd_restore();

  Fd_restore &operator=(Fd_restore const &) = delete;
  Fd_restore &operator=(Fd_restore &&) = delete;
};

struct Tmp_fd_remap {
  Fd_restore const m_restore;

  Tmp_fd_remap(int from_fd, int to_fd);
};

bool operator==(ether_addr const &lhs, ether_addr const &rhs);

std::ostream &operator<<(std::ostream &out, ether_addr const &ether_addr);

struct Pcap_dummy : public Pcap_wrapper {
  Pcap_wrapper::Loop_end_reason loop_return;

  Pcap_dummy();

  using Pcap_wrapper::get_end_reason;

  void set_loop_return(Pcap_wrapper::Loop_end_reason const &ler);

  Pcap_wrapper::Loop_end_reason
  loop(int count,
       std::function<void(const struct pcap_pkthdr *, const u_char *)> cb)
      override;
};

std::string get_executable_path();

std::string get_executable_directory();
