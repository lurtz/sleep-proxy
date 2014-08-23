#include "ethernet.h"
#include <iterator>
#include <stdexcept>
#include <sstream>
#include "container_utils.h"

std::ostream& operator<<(std::ostream& out, const Link_layer& ll) {
        out << ll.get_info();
        return out;
}

size_t Linux_cooked_capture::header_length() const {
        return 16;
}

uint16_t Linux_cooked_capture::payload_protocol() const {
        return payload_type;
}

std::string Linux_cooked_capture::get_info() const {
        return "Linux cooked capture";
}


size_t VLAN_Header::header_length() const {
        return 4;
}

uint16_t VLAN_Header::payload_protocol() const {
        return payload_type;
}

std::string VLAN_Header::get_info() const {
        return "VLAN Header";
}

size_t sniff_ethernet::header_length() const {
        return 14;
}

uint16_t sniff_ethernet::payload_protocol() const {
        return ether_type;
}

std::string sniff_ethernet::destination() const {
        return join(ether_dhost, [](int i){return i;}, ":");
}

std::string sniff_ethernet::source() const {
        return join(ether_shost, [](int i){return i;}, ":");
}

std::string sniff_ethernet::get_info() const {
        return "Ethernet: dst = " + destination() + ", src = " + source();
}

