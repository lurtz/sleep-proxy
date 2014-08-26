#include "pcap_wrapper.h"
#include <iostream>
#include <stdexcept>
#include "to_string.h"

/** provides a bpf_programm instance in an exception safe way */
struct BPF {
        bpf_program bpf;
        BPF(std::unique_ptr<pcap_t, std::function<void(pcap_t*)>>& pc, const std::string& filter) {
                if (pcap_compile(pc.get(), &bpf, filter.c_str(), false, PCAP_NETMASK_UNKNOWN) == -1) {
                        throw std::runtime_error("Can't compile bpf filter " + filter);
                }
        }
        ~BPF() {
                pcap_freecode(&bpf);
        }
};

Pcap_wrapper::Pcap_wrapper() : pc(nullptr) {}

Pcap_wrapper::Pcap_wrapper(const std::string iface, const int snaplen, const bool promisc, const int timeout) : pc(pcap_create(iface.c_str(), errbuf.data()), pcap_close) {
        if (pc == nullptr) {
                throw std::runtime_error(errbuf.data());
        }
        if (pcap_set_snaplen(pc.get(), snaplen) == PCAP_ERROR_ACTIVATED) {
                throw std::runtime_error("interface: " + iface + " can't set snaphot length: " + to_string(snaplen));
        }
        if (pcap_set_promisc(pc.get(), promisc) != 0) {
                throw std::runtime_error("interface: " + iface + " can't deactivate promiscuous mode");
        }
        if (pcap_set_timeout(pc.get(), timeout) != 0) {
                throw std::runtime_error("interface: " + iface + " can't deactivate timeout");
        }
        if (pcap_activate(pc.get()) == -1) {
                throw std::runtime_error("interface: " + iface + " can't activate selected interface: " + iface);
        }
	std::cout << "datalink " << get_verbose_datalink() << std::endl;
}

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
                case DLT_LINUX_SLL: return "Linux cooked socket";
		case DLT_EN10MB: return "ethernet";
		default: return "unknown";
	}
}

void Pcap_wrapper::set_filter(const std::string& filter) {
        BPF bpf(pc, filter);
        if (pcap_setfilter(pc.get(), &bpf.bpf) == -1) {
                throw std::runtime_error("Couldn't install filter " + filter + ": " + pcap_geterr(pc.get()));
        }
}

/**
 * provide a way to pass std::function objects as an callback to the C++
 * interface. this function is called inside the C library and calls the C++
 * functor
 */
void callback_wrapper(u_char * args, const struct pcap_pkthdr * header, const u_char * packet) {
        auto cb = *reinterpret_cast<std::function<void(const struct pcap_pkthdr *, const u_char *)> *>(args);
        cb(header, packet);
}

Pcap_wrapper::Loop_end_reason Pcap_wrapper::loop(const int count, std::function<void(const struct pcap_pkthdr *, const u_char *)> cb) {
        const int ret_val = pcap_loop(pc.get(), count, callback_wrapper, reinterpret_cast<u_char *>(&cb));
        switch (ret_val) {
                case 0:
                        loop_end_reason = Loop_end_reason::packets_captured;
                        break;
                case -1:
                        loop_end_reason = Loop_end_reason::error;
                        throw std::runtime_error(std::string("error while captching data: ") + pcap_geterr(pc.get()));
                        break;
                case -2:
                        break;

        }
        return loop_end_reason;
}

void Pcap_wrapper::break_loop(const Loop_end_reason& ler) {
        loop_end_reason = ler;
        if (pc != nullptr)
                pcap_breakloop(pc.get());
}

