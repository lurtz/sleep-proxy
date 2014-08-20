#include <string>
#include <stdexcept>
#include <iostream>
#include <memory>
#include <vector>
#include <tuple>
#include <cassert>
#include <map>
#include <mutex>
#include "split.h"
#include "pcap_wrapper.h"
#include "ethernet.h"
#include "ip.h"
#include "tp.h"
#include "scope_guard.h"
#include "ip_utils.h"
#include "args.h"
#include "to_string.h"
#include "container_utils.h"
#include "libemulateHost.h"
#include "spawn_process.h"
#include "wol.h"

/*
 * Pretends to be a host, which has gone into standby and is startable via wake
 * on lan. Upon an incoming connection the host is waked up and the next/second
 * TCP SYN packet from the client will reach the host. The first SYN packet is
 * lost because the pretending one received it.
 *
 * This programm adds the IPs of the sleeping hosts to this machine and adds
 * firewall rules to filter RST packets to the clients.
 */

/** used to break the loop using a signal handler */
std::mutex pcaps_mutex;
std::vector<Pcap_wrapper *> pcaps;

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
 * Ethernet, IP and TCP/UDP header in one tuple
 * */
typedef std::tuple<std::unique_ptr<Link_layer>, std::unique_ptr<ip>, std::unique_ptr<tp>> basic_headers;

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

/**
 * If used as pcap callback prints some info about the received data
 * */
struct Got_packet {
        const int link_layer_type;
        void operator()(const struct pcap_pkthdr *header, const u_char *packet) {
                if (header == nullptr || packet == nullptr) {
                        std::cerr << "header or packet are nullptr" << std::endl;
                        return;
                }
                std::cout << *header << std::endl;
                basic_headers headers = get_headers(link_layer_type, std::vector<u_char>(packet, packet + header->len));
                print_packet(headers);
        }
};

/**
 * Saves the lower 3 layers and all the data which has been intercepted
 * using pcap.
 */
struct Catch_incoming_connection {
        const int link_layer_type;
        basic_headers headers;
        std::vector<uint8_t> data;

        Catch_incoming_connection(const int link_layer_typee) : link_layer_type(link_layer_typee) {}

        void operator()(const pcap_pkthdr * header, const u_char * packet) {
                if (header == nullptr || packet == nullptr) {
                        std::cerr << "header or packet are nullptr" << std::endl;
                        return;
                }
                data = std::vector<uint8_t>(packet, packet + header->len);
                headers = get_headers(link_layer_type, data);
        }
};

/**
 * Adds from args the IPs to the machine and setups the firewall
 */
std::vector<Scope_guard> setup_firewall_and_ips(const Args& args) {
        std::vector<Scope_guard> guards;
        for (auto& ip : args.address) {
                // setup firewall first, otherwise a buffer of an IP might
                // get filled
                // reject any incoming connection, except the ones to the
                // ports specified
                guards.emplace_back(Reject_tp{ip, Reject_tp::TP::TCP});
                guards.emplace_back(Reject_tp{ip, Reject_tp::TP::UDP});
                for (auto& port : args.ports) {
                        guards.emplace_back(Open_port{ip, port});
                }
                // no one open opened the ports, block RST packets from being
                //sent to the client
                guards.emplace_back(Block_rst{ip});
                guards.emplace_back(Temp_ip{args.interface, ip});
        }
        return guards;
}

/**
 * Waits and blocks until a SYN packet to any of the given IPs in Args and to
 * any of the given ports in Args is received. Returns the data, the IP
 * source of the received packet and the destination IP
 */
std::tuple<std::vector<uint8_t>, std::string, std::string> wait_and_listen(const Args& args) {
        Pcap_wrapper pc("any");
        Scope_guard pc_guard{ptr_guard(pcaps, pcaps_mutex, pc)};
        std::string bpf = "tcp";
        bpf += " and dst host (" + join(args.address, get_pure_ip, " or ") + ")";
        bpf += " and dst port (" + join(args.ports, [](uint16_t in){return in;}, " or ") + ")";
        std::cout << "Listening with filter: " + bpf << std::endl;
        pc.set_filter(bpf);
        std::cout << "listen" << std::endl;
        Catch_incoming_connection catcher(pc.get_datalink());
        pc.loop(1, [&](const pcap_pkthdr * header, const u_char * packet) { catcher(header, packet);});
        print_packet(catcher.headers);
	if (std::get<1>(catcher.headers) == nullptr) {
		throw std::runtime_error("got nothing while catching with pcap");
	}
        return std::make_tuple(catcher.data, std::get<1>(catcher.headers)->source(), std::get<1>(catcher.headers)->destination());
}

std::string get_ping_cmd(const std::string& ip) {
        std::map<int, std::string> which_pingcmd{{AF_INET, "ping"}, {AF_INET6, "ping6"}};
        return get_path(which_pingcmd.at(getAF(ip)));
}

std::string get_bindable_ip(const std::string& iface, const std::string& ip) {
        if (ip.find("fe80") == 0) {
                return get_pure_ip(ip) + '%' + iface;
        } else {
                return get_pure_ip(ip);
        }
}

bool ping_and_wait(const std::string& iface, const std::string& ip, const unsigned int tries) {
        std::string ipcmd = get_ping_cmd(ip);
        std::string cmd{ipcmd + " -c 1 " + get_bindable_ip(iface, ip)};
        std::cout << cmd << std::endl;
        for (unsigned int i = 0; i < tries; i++) {
                pid_t pid = spawn(split(cmd, ' '));
                uint8_t ret_val = wait_until_pid_exits(pid);
                if (ret_val == 0) {
                        return true;
                }
        }
        return false;
}

/**
 * Puts everything together. Sets up firewall and IPs. Waits for an incoming
 * SYN packet and wakes the sleeping host via WOL
 */
void emulate_host(const Args& args) {
        // setup firewall rules and add IPs to the interface
        std::vector<Scope_guard> locks(setup_firewall_and_ips(args));
        // wait until upon an incoming connection
        auto data_source_destination = wait_and_listen(args);
        std::cout << "got something" << std::endl;
        // block icmp messages to the source IP, e.g. not tell him that his
        // destination IP is gone for a short while
        Scope_guard block_icmp(Block_icmp{std::get<1>(data_source_destination)});
        // release_locks()
        locks.clear();
        // wake the sleeping server
        wol_ethernet(args.interface, args.mac);
        // wait until server responds and release ICMP rules
        ping_and_wait(args.interface, std::get<2>(data_source_destination), args.ping_tries);
}

void test_pcap() {
        Pcap_wrapper pc("lo");
        pc.set_filter("tcp and port 12345");
        std::cout << "höre" << std::endl;
        Got_packet gp{pc.get_datalink()};
        pc.loop(1, gp);
        std::cout << "fertig" << std::endl;
}

void signal_handler(int) {
        std::lock_guard<std::mutex> lock(pcaps_mutex);
        for (auto& pc : pcaps) {
                pc->break_loop();
        }
}

