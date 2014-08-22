#include "packet_parser.h"

/**
 * Writes time formatted into the stream
 * */
std::ostream& operator<<(std::ostream& out, struct timeval time) {
        out << time.tv_sec << "." << time.tv_usec << " s";
        return out;
}

/**
 * Writes hdr formatted into the stream
 */
std::ostream& operator<<(std::ostream& out, const pcap_pkthdr& hdr) {
        out << "[" << hdr.ts << "]: length:" << hdr.len << ", supposed length: " << hdr.caplen;
        return out;
}

/**
 * Extracts the Ethernet, IP and TCP/UDP headers from packet
 * */
basic_headers get_headers(const int type, const std::vector<u_char>& packet) {
        std::vector<u_char>::const_iterator data = std::begin(packet);
        std::vector<u_char>::const_iterator end = std::end(packet);

        // link layer header
        std::unique_ptr<Link_layer> ll = parse_link_layer(type, data, end);
        if (ll == nullptr) {
                std::cerr << "unsupported link layer protocol: " << type << std::endl;
                return std::make_tuple(std::unique_ptr<Link_layer>(nullptr), std::unique_ptr<ip>(nullptr), std::unique_ptr<tp>(nullptr));
        }
        data += static_cast<std::vector<u_char>::const_iterator::difference_type>(ll->header_length());

        // IP header
        std::unique_ptr<ip> ipp = parse_ip(ll->payload_protocol(), data, end);
        if (ipp == nullptr) {
                std::cerr << "unsupported link layer payload: " << static_cast<unsigned int>(ll->payload_protocol()) << std::endl;
                return std::make_tuple(std::move(ll), std::unique_ptr<ip>(nullptr), std::unique_ptr<tp>(nullptr));
        }
        data += static_cast<std::vector<u_char>::const_iterator::difference_type>(ipp->header_length());

        // TCP/UDP header
        std::unique_ptr<tp> tpp = parse_tp(ipp->payload_protocol(), data, end);
        if (tpp == nullptr) {
                std::cerr << "unsupported ip payload: " << static_cast<unsigned int>(ipp->payload_protocol()) << std::endl;
        }

        return std::make_tuple(std::move(ll), std::move(ipp), std::move(tpp));
}

/**
 * Prints the headers to std::cout
 * */
void print_packet(const basic_headers& headers) {
        if (std::get<1>(headers) == nullptr || std::get<2>(headers) == nullptr) {
                std::cerr << "some headers could not be parsed" << std::endl;
                return;
        }
        const Link_layer& ll = *std::get<0>(headers);
        const ip& ip = *std::get<1>(headers);
        const tp& tp = *std::get<2>(headers);
        std::cout << ll << std::endl << ip << std::endl << tp << std::endl;
}

void Got_packet::operator()(const struct pcap_pkthdr *header, const u_char *packet) {
        if (header == nullptr || packet == nullptr) {
                std::cerr << "header or packet are nullptr" << std::endl;
                return;
        }
        std::cout << *header << std::endl;
        basic_headers headers = get_headers(link_layer_type, std::vector<u_char>(packet, packet + header->len));
        print_packet(headers);
}

Catch_incoming_connection::Catch_incoming_connection(const int link_layer_typee) : link_layer_type(link_layer_typee) {}

void Catch_incoming_connection::operator()(const pcap_pkthdr * header, const u_char * packet) {
        if (header == nullptr || packet == nullptr) {
                std::cerr << "header or packet are nullptr" << std::endl;
                return;
        }
        data = std::vector<uint8_t>(packet, packet + header->len);
        headers = get_headers(link_layer_type, data);
}

