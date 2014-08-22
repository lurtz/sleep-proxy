#include "pcap_wrapper.h"
#include "packet_parser.h"

void test_pcap() {
        Pcap_wrapper pc("lo");
        pc.set_filter("tcp and port 12345");
        std::cout << "höre" << std::endl;
        Got_packet gp{pc.get_datalink()};
        pc.loop(1, gp);
        std::cout << "fertig" << std::endl;
}

int main(int argc, char * argv[]) {
        Pcap_wrapper pcap(argv[1]);
        pcap.set_filter(argv[2]);
        return 0;
}
