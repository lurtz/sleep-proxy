#pragma once

#include <iostream>
#include <vector>
#include <array>
#include <arpa/inet.h>
#include <pcap/bpf.h>
#include <memory>

struct Link_layer {

        template<typename iterator>
        Link_layer(iterator data, iterator end) {
                static_assert(std::is_same<typename iterator::value_type, uint8_t>::value, "container has to carry u_char or uint8_t");
                if (data >= end) {
                        throw std::range_error("data iterator past the end");
                }
        }

        virtual ~Link_layer() {}

        virtual size_t header_length() const = 0;

        virtual uint16_t payload_protocol() const = 0;

        virtual std::string get_info() const = 0;
};

std::ostream& operator<<(std::ostream& out, const Link_layer&);

struct Linux_cooked_capture : public Link_layer {
        private:
        uint16_t payload_type;

        public:
        template<typename iterator>
        Linux_cooked_capture(iterator data, iterator end) : Link_layer(data, end) {
                if (static_cast<size_t>(end - data) < header_length()) {
                        throw std::length_error("not enough data to construct an ethernet header");
                }
                data += 14;
                payload_type = ntohs(*reinterpret_cast<uint16_t const *>(&(*data)));
        }

        virtual size_t header_length() const;

        virtual uint16_t payload_protocol() const;

        virtual std::string get_info() const;
};

/** Ethernet header with destination address, source address and payload type */
struct sniff_ethernet : public Link_layer {
        /** Ethernet addresses are 6 bytes */
        static const unsigned int ETHER_ADDR_LEN = 6;
        private:
        /* Destination host address */
        std::array<u_char, ETHER_ADDR_LEN> ether_dhost;
        /* Source host address */
        std::array<u_char, ETHER_ADDR_LEN> ether_shost;
        /* IP? ARP? RARP? etc */
        u_short ether_type;

        public:
        /**
         * constructs an ethernet header from data and checks using end that
         * enough bytes are present
         */
        template<typename iterator>
        sniff_ethernet(iterator data, iterator end) : Link_layer(data, end) {
                if (static_cast<size_t>(end - data) < header_length()) {
                        throw std::length_error("not enough data to construct an ethernet header");
                }
                std::copy(data, data+ETHER_ADDR_LEN, std::begin(ether_dhost));
                data += ETHER_ADDR_LEN;
                std::copy(data, data+ETHER_ADDR_LEN, std::begin(ether_shost));
                data += ETHER_ADDR_LEN;
                ether_type = ntohs(*reinterpret_cast<u_short const *>(&(*data)));
        }

        /**
         * size of an ethernet header
         */
        virtual size_t header_length() const;

        /**
         * which protocol is to expect next
         */
        virtual uint16_t payload_protocol() const;

        /**
         * destination address
         */
        std::string destination() const;

        /**
         * source address
         */
        std::string source() const;

        virtual std::string get_info() const;
};

/** writes destination and source from eth into out */
std::ostream& operator<<(std::ostream& out, const sniff_ethernet& eth);

template<typename iterator>
std::unique_ptr<Link_layer> parse_link_layer(const int type, iterator data, iterator end) {
        switch (type) {
                case DLT_LINUX_SLL: return std::unique_ptr<Link_layer>(new Linux_cooked_capture(data, end));
                case DLT_EN10MB: return std::unique_ptr<Link_layer>(new sniff_ethernet(data, end));
                default: return std::unique_ptr<Link_layer>(nullptr);
        }
}
