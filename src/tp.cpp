#include "tp.h"

std::string tp::extra_info() const { return ""; }

std::ostream& operator<<(std::ostream& out, const tp& tp) {
        out << tp.type() << ": src port = " << tp.source() << ", ";
        out << "destination = " << tp.destination() << ", " << tp.extra_info();
        return out;
}

size_t sniff_tcp::header_length() const {
        return ((th_offx2 & 0xf0) >> 4) * 4;
}
std::string sniff_tcp::type() const {
        return "TCP";
}
uint16_t sniff_tcp::source() const {
        return th_sport;
}
uint16_t sniff_tcp::destination() const {
        return th_dport;
}
std::string sniff_tcp::extra_info() const {
        std::string retval("Flags: ");
        if (th_flags & TH_FIN)
                retval += "FIN,";
        if (th_flags & TH_SYN)
               retval += "SYN,";
        if (th_flags & TH_RST)
               retval += "RST,";
        if (th_flags & TH_PUSH)
               retval += "PUSH,";
        if (th_flags & TH_ACK)
               retval += "ACK,";
        if (th_flags & TH_URG)
               retval += "URG,";
        if (th_flags & TH_ECE)
               retval += "ECE,";
        if (th_flags & TH_CWR)
               retval = "CWR,";
        return retval.substr(0, retval.size() - 1);
}

std::string sniff_udp::type() const {
        return "UDP";
}
uint16_t sniff_udp::source() const {
        return source_port;
}
uint16_t sniff_udp::destination() const {
        return destination_port;
}
size_t sniff_udp::header_length() const {
        return 8;
}

