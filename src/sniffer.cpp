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

#include "error_suppression.h"
#include "ethernet.h"
#include "log.h"
#include "packet_parser.h"
#include "pcap_wrapper.h"
#include <cstddef>
#include <cstdlib>
#include <iterator>
#include <span>

/**
 * Writes time formatted into the stream
 * */
inline std::ostream &operator<<(std::ostream &out, struct timeval time) {
  out << time.tv_sec << "." << time.tv_usec << " s";
  return out;
}

/**
 * Writes hdr formatted into the stream
 */
inline std::ostream &operator<<(std::ostream &out, const pcap_pkthdr &hdr) {
  out << "[" << hdr.ts << "]: length:" << hdr.len
      << ", supposed length: " << hdr.caplen;
  return out;
}

namespace {
/**
 * If used as pcap callback prints some info about the received data
 * */
struct Got_packet {
  const int link_layer_type;
  void operator()(const struct pcap_pkthdr *header,
                  const u_char *packet) const {
    if (header == nullptr || packet == nullptr) {
      log_string(LOG_ERR, "header or packet are nullptr");
      return;
    }
    log_string(LOG_INFO, *header);
    const auto *end_iter = packet;
    std::advance(end_iter, header->len);
    basic_headers headers =
        get_headers(link_layer_type, std::vector<u_char>(packet, end_iter));
    log_string(LOG_INFO, headers);
  }
};

void print_help() { log_string(LOG_NOTICE, "usage: iface bpf_filter"); }
} // namespace

int main(int argc, char *argv[]) {
  if (argc != 3) {
    print_help();
    return EXIT_FAILURE;
  }

  IGNORE_CLANG_WARNING
  std::span<char *> const args{argv, static_cast<size_t>(argc)};
  REENABLE_CLANG_WARNING

  Pcap_wrapper pcap(args[1]);
  pcap.set_filter(args[2]);
  pcap.loop(0, Got_packet{pcap.get_datalink()});
  return EXIT_SUCCESS;
}
