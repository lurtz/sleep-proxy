#include <string>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <tuple>
#include <map>
#include <mutex>
#include "split.h"
#include "pcap_wrapper.h"
#include "scope_guard.h"
#include "ip_utils.h"
#include "args.h"
#include "container_utils.h"
#include "libsleep_proxy.h"
#include "spawn_process.h"
#include "wol.h"
#include "packet_parser.h"

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
                guards.emplace_back(Duplicate_address_watcher{ip});
                guards.emplace_back(Temp_ip{args.interface, ip});
                // block any outgoing packets from args.interface
                guards.emplace_back(Reject_outgoing_tcp{ip});
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
        pc.loop(1, std::ref(catcher));
	if (std::get<1>(catcher.headers) == nullptr) {
		throw std::runtime_error("got nothing while catching with pcap");
	}
        std::cout << catcher.headers << std::endl;
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

void signal_handler(int) {
        std::lock_guard<std::mutex> lock(pcaps_mutex);
        for (auto& pc : pcaps) {
                pc->break_loop(Pcap_wrapper::Loop_end_reason::signal);
        }
}

