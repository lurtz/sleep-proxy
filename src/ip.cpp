#include "ip.h"
#include <arpa/inet.h>
#include "to_string.h"

std::ostream& operator<<(std::ostream& out, const in_addr& ip) {
        char addr[INET6_ADDRSTRLEN];
        out << inet_ntop(AF_INET, &(ip.s_addr), addr, INET6_ADDRSTRLEN);
        return out;
}

std::ostream& operator<<(std::ostream& out, const in6_addr& ip) {
        char addr[INET6_ADDRSTRLEN];
        out << inet_ntop(AF_INET6, ip.s6_addr, addr, INET6_ADDRSTRLEN);
        return out;
}

std::ostream& operator<<(std::ostream& out, const ip& ip) {
        out << "IPv" << static_cast<unsigned int>(ip.version()) << ": ";
        out << "dst = " << ip.destination() << ", src = " << ip.source() << ", ";
        return out;
}

uint8_t sniff_ipv4::version() const {
        return ip_vhl >> 4;
}
size_t sniff_ipv4::header_length() const {
        return (ip_vhl & 0x0f) * 4;
}
std::string sniff_ipv4::source() const {
        return to_string(ip_src);
}
std::string sniff_ipv4::destination() const {
        return to_string(ip_dst);
}
uint8_t sniff_ipv4::payload_protocol() const {
        return ip_p;
}

uint8_t sniff_ipv6::version() const {
        return version_trafficclass_flowlabel >> 28;
}
size_t sniff_ipv6::header_length() const {
        return 40;
}
std::string sniff_ipv6::source() const {
        return to_string(source_address);
}
std::string sniff_ipv6::destination() const {
        return to_string(dest_address);
}
uint32_t sniff_ipv6::traffic_class() const {
        return (version_trafficclass_flowlabel >> 20) & 0xff;
}
uint32_t sniff_ipv6::flow_label() const {
        return version_trafficclass_flowlabel & 0xfffff;
}
uint8_t sniff_ipv6::payload_protocol() const {
        return next_header;
}

