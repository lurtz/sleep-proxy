#pragma once

#include <string>

void wol_udp(const std::string& mac);
void wol_ethernet(const std::string& iface, const std::string& mac);

