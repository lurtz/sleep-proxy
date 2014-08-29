#include "pcap_wrapper.h"
#include "packet_parser.h"
#include "log.h"

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
 * If used as pcap callback prints some info about the received data
 * */
struct Got_packet {
        const int link_layer_type;
        void operator()(const struct pcap_pkthdr *header, const u_char *packet) {
                if (header == nullptr || packet == nullptr) {
                        log_string(LOG_ERR, "header or packet are nullptr");
                        return;
                }
                log_string(LOG_INFO, *header);
                basic_headers headers = get_headers(link_layer_type, std::vector<u_char>(packet, packet + header->len));
                log_string(LOG_INFO, headers);
        }
};

void print_help() {
        log_string(LOG_NOTICE, "usage: iface bpf_filter");
}

int main(int argc, char * argv[]) {
        if (argc != 3) {
                print_help();
                return 1;
        }
        Pcap_wrapper pcap(argv[1]);
        pcap.set_filter(argv[2]);
        pcap.loop(0, Got_packet{pcap.get_datalink()});
        return 0;
}
