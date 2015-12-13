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

#include <functional>
#include <algorithm>
#include <mutex>
#include <memory>
#include "pcap_wrapper.h"
#include "ip_address.h"

/** perform or reverse the modification */
enum struct Action { add, del };

/**
 * Upon creation consume a resource or perform a modification. Upon deletion
 * reverse this modification.
 */
struct Scope_guard {
  typedef std::function<std::string(const Action)> Aquire_release;

private:
  /** if the consumed resource or modification is freed */
  bool freed;
  /** function to take or release */
  const Aquire_release aquire_release;

  /**
   * Consume or free the resource
   */
  void take_action(const Action a) const;

public:
  /**
   * Default constructor initializes anything with default values
   */
  Scope_guard();

  /**
   * consume the resource or perform modification using
   * aquire_release_arg
   */
  Scope_guard(Aquire_release &&aquire_release_arg);

  /**
   * Move constructor
   */
  Scope_guard(Scope_guard &&rhs);

  ~Scope_guard();

  /**
   * Deleted to prevent freeing the same resource more than once
   */
  Scope_guard(const Scope_guard &) = delete;

  /**
   * Deleted to prevent freeing the same resource more than once
   */
  Scope_guard &operator=(const Scope_guard &) = delete;

  /**
   * Checks if the resource is already freed and frees them if not
   */
  void free();
};

/** Adds ip to iface, removes it afterwards */
struct Temp_ip {
  const std::string iface;
  const IP_address ip;

  std::string operator()(const Action action) const;
};

/** Adds a firewall rule to open port for ip */
struct Drop_port {
  const IP_address ip;
  const uint16_t port;

  std::string operator()(const Action action) const;
};

/** Adds a firewall rule to reject either TCP or UDP packets */
struct Reject_tp {
  enum struct TP { TCP, UDP };
  const IP_address ip;
  const TP tcp_udp;

  std::string operator()(const Action action) const;
};

/** Adds a firewall rule to block ICMP messages directed to ip */
struct Block_icmp {
  const IP_address ip;

  std::string operator()(const Action action) const;
};

struct Block_ipv6_neighbor_solicitation {
  const IP_address ip;

  std::string operator()(const Action action) const;
};

/** adds and removes an element of type T to container of type Cont */
template <typename Cont, typename T> struct Ptr_guard {
  Cont &cont;
  std::mutex &cont_mutex;
  T &ref;

  std::string operator()(const Action action) {
    const std::lock_guard<std::mutex> lock(cont_mutex);
    switch (action) {
    case Action::add:
      cont.emplace_back(&ref);
      break;
    case Action::del: {
      const auto pos = std::find(std::begin(cont), std::end(cont), &ref);
      if (pos == std::end(cont)) {
        throw std::runtime_error("element supposed to be managed by ptr_guard "
                                 "is gone missing from container");
      }
      cont.erase(pos);
      break;
    }
    default:
      break;
    }
    return "";
  }
};

template <typename Cont, typename T>
Ptr_guard<Cont, T> ptr_guard(Cont &cont, std::mutex &cont_mutex, T &ref) {
  return Ptr_guard<Cont, T>{cont, cont_mutex, ref};
}

template <typename FUNCTOR> struct Moveable_functor_wrapper {
  std::shared_ptr<FUNCTOR> functor;

  std::string operator()(const Action action) { return (*functor)(action); }
};

template <typename MOVEABLE, typename... ARGS>
Moveable_functor_wrapper<MOVEABLE> make_copyable(ARGS... args) {
  return Moveable_functor_wrapper<MOVEABLE>{
      std::make_shared<MOVEABLE>(args...)};
}
