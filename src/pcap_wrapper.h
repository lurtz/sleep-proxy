#pragma once

#include <pcap/pcap.h>
#include <string>
#include <memory>

/** Provide a nice interface to pcap and close the handle upon an exception */
struct Pcap_wrapper {
        enum class Loop_end_reason {unset, packets_captured, signal, duplicate_address, error};
        private:
        /** error buffer */
        std::array<char, PCAP_ERRBUF_SIZE> errbuf{{0}};
        /** pointer to the opened pcap_t struct with its close function */
        std::unique_ptr<pcap_t, std::function<void(pcap_t*)>> pc;
        Loop_end_reason loop_end_reason = Loop_end_reason::unset;

        public:
        /** open a pcap instance on iface */
        Pcap_wrapper(const std::string iface, const int snaplen = 65000, const bool promisc = false, const int timeout = 1000);

        /** tell if the first header is ethernet, unix socket, ... */
        int get_datalink() const;

        std::string get_verbose_datalink() const;

        /** sets a BPF (berkeley packet filter) filter the pcap instance */
        void set_filter(const std::string& filter);

        /** sniff count packets calling cb each time */
        Pcap_wrapper::Loop_end_reason loop(const int count, std::function<void(const struct pcap_pkthdr *, const u_char *)> cb);

        void break_loop(const Loop_end_reason&);
};

