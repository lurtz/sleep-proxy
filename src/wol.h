#pragma once

#include <string>

void wol_udp(const std::string& mac);
// TODO from dmesg: [10748.090978] emulateHost uses obsolete (PF_INET,SOCK_PACKET)
void wol_ethernet_pcap(const std::string& iface, const std::string& mac);
void wol_ethernet(const std::string& iface, const std::string& mac);

