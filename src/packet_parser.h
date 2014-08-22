#pragma once

#include <tuple>
#include <memory>
#include <vector>
#include <pcap/pcap.h>
#include "ethernet.h"
#include "ip.h"
#include "tp.h"

/**
 * Ethernet, IP and TCP/UDP header in one tuple
 * */
typedef std::tuple<std::unique_ptr<Link_layer>, std::unique_ptr<ip>, std::unique_ptr<tp>> basic_headers;

/**
 * Extracts the Ethernet, IP and TCP/UDP headers from packet
 * */
basic_headers get_headers(const int type, const std::vector<u_char>& packet);

/**
 * Prints the headers to std::cout
 * */
void print_packet(const basic_headers& headers);

/**
 * If used as pcap callback prints some info about the received data
 * */
struct Got_packet {
        const int link_layer_type;
        void operator()(const struct pcap_pkthdr *header, const u_char *packet);
};

/**
 * Saves the lower 3 layers and all the data which has been intercepted
 * using pcap.
 */
struct Catch_incoming_connection {
        const int link_layer_type;
        basic_headers headers;
        std::vector<uint8_t> data;

        Catch_incoming_connection(const int link_layer_typee);

        void operator()(const pcap_pkthdr * header, const u_char * packet);
};

void test_pcap();

