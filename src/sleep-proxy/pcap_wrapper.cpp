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

#include "pcap_wrapper.h"

#include "log.h"
#include "to_string.h"
#include <mutex>
#include <pthread.h>
#include <stdexcept>

namespace {
/**
 * provide a way to pass std::function objects as an callback to the C++
 * interface. this function is called inside the C library and calls the C++
 * functor
 */
void callback_wrapper(u_char *args, const struct pcap_pkthdr *header,
                      const u_char *packet) {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  auto *const cb = reinterpret_cast<Pcap_wrapper::Callback_t *>(args);
  (*cb)(header, packet);
}

std::function<void(pcap_t *const, int const, Pcap_wrapper::Callback_t)>
create_loop(int &ret_val) {
  auto loop_f = [&ret_val](pcap_t *const pcc, const int count,
                           Pcap_wrapper::Callback_t cb) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *const args = reinterpret_cast<u_char *>(&cb);
    ret_val = pcap_loop(pcc, count, callback_wrapper, args);
  };
  return loop_f;
}
} // namespace

/** provides a bpf_programm instance in an exception safe way */
struct BPF {
  bpf_program bpf;
  BPF(std::unique_ptr<pcap_t, void (*)(pcap_t *)> &pc,
      const std::string &filter)
      : bpf{.bf_len = 0, .bf_insns = nullptr} {
    // pcap_compile is not thread safe
    // see http://seclists.org/tcpdump/2012/q2/22
    static std::mutex pcap_compile_mutex;
    std::lock_guard<std::mutex> const lock(pcap_compile_mutex);
    if (pcap_compile(pc.get(), &bpf, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) ==
        -1) {
      throw std::runtime_error("Can't compile bpf filter " + filter);
    }
  }
  BPF(BPF const &) = delete;
  BPF(BPF &&) = delete;
  ~BPF() { pcap_freecode(&bpf); }
  BPF &operator=(BPF const &) = delete;
  BPF &operator=(BPF &&) = delete;
};

Pcap_wrapper::Pcap_wrapper()
    : pc(nullptr, pcap_close), loop_thread{},
      loop_end_reson_mutex{std::make_unique<std::mutex>()} {}

Pcap_wrapper::Loop_end_reason Pcap_wrapper::get_end_reason() const {
  std::lock_guard<std::mutex> const lock{*loop_end_reson_mutex};
  return loop_end_reason;
}

Pcap_wrapper::Pcap_wrapper(const std::string &iface, const int snaplen,
                           const bool promisc, const int timeout)
    : pc(pcap_create(iface.c_str(), errbuf.data()), pcap_close), loop_thread{},
      loop_end_reson_mutex{std::make_unique<std::mutex>()} {
  if (pc == nullptr) {
    throw std::runtime_error(errbuf.data());
  }
  if (pcap_set_snaplen(pc.get(), snaplen) == PCAP_ERROR_ACTIVATED) {
    throw std::runtime_error(
        "interface: " + iface +
        " can't set snaphot length: " + to_string(snaplen));
  }
  if (pcap_set_promisc(pc.get(), static_cast<int>(promisc)) != 0) {
    throw std::runtime_error("interface: " + iface +
                             " can't deactivate promiscuous mode");
  }
  if (pcap_set_timeout(pc.get(), timeout) != 0) {
    throw std::runtime_error("interface: " + iface +
                             " can't deactivate timeout");
  }
  if (pcap_activate(pc.get()) == -1) {
    throw std::runtime_error("interface: " + iface +
                             " can't activate selected interface: " + iface);
  }
  log_string(LOG_INFO, "datalink " + get_verbose_datalink());
}

Pcap_wrapper::~Pcap_wrapper() = default;

int Pcap_wrapper::get_datalink() const {
  int datalink = pcap_datalink(pc.get());
  if (datalink == PCAP_ERROR_NOT_ACTIVATED) {
    throw std::runtime_error("can't get datalink type");
  }
  return datalink;
}

std::string Pcap_wrapper::get_verbose_datalink() const {
  const int datalink = get_datalink();
  switch (datalink) {
  case DLT_LINUX_SLL:
    return "Linux cooked socket";
  case DLT_EN10MB:
    return "ethernet";
  default:
    return "unknown";
  }
}

void Pcap_wrapper::set_filter(const std::string &filter) {
  BPF bpf(pc, filter);
  if (pcap_setfilter(pc.get(), &bpf.bpf) == -1) {
    throw std::runtime_error("Couldn't install filter " + filter + ": " +
                             pcap_geterr(pc.get()));
  }
}

Pcap_wrapper::Loop_end_reason Pcap_wrapper::loop(const int count,
                                                 Callback_t cb) {
  int ret_val = 1;
  auto loop_f = create_loop(ret_val);

  loop_thread = std::thread{loop_f, pc.get(), count, std::move(cb)};
  loop_thread.join();

  std::lock_guard<std::mutex> const lock{*loop_end_reson_mutex};
  switch (ret_val) {
  case 0:
    loop_end_reason = Loop_end_reason::packets_captured;
    break;
  case PCAP_ERROR:
    loop_end_reason = Loop_end_reason::error;
    throw std::runtime_error(std::string("error while captching data: ") +
                             pcap_geterr(pc.get()));
  default:
    break;
  }
  return loop_end_reason;
}

void Pcap_wrapper::break_loop(const Loop_end_reason &ler) {
  {
    std::lock_guard<std::mutex> const lock{*loop_end_reson_mutex};
    loop_end_reason = ler;
  }
  if (pc != nullptr) {
    pcap_breakloop(pc.get());
  }
  if (loop_thread.joinable()) {
    pthread_cancel(loop_thread.native_handle());
  }
}

int Pcap_wrapper::inject(const std::vector<uint8_t> &data) {
  int bytes = pcap_inject(pc.get(), data.data(), data.size());
  if (bytes == -1) {
    throw std::runtime_error(std::string("pcap_inject() failed: ") +
                             pcap_geterr(pc.get()));
  }
  return bytes;
}
