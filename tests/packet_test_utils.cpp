#include "packet_test_utils.h"
#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/extensions/HelperMacros.h>
#include "container_utils.h"
#include "int_utils.h"

void check_range(const long long int val, const long long int lower, const long long int upper) {
        if (val < lower || val >= upper) {
                throw std::out_of_range(to_string(val) + " is not in range [" + to_string(lower) + "," + to_string(upper) + ")");
        }
}

/**
 * converts two hex characters into a byte value
 */
uint8_t two_hex_chars_to_byte(const char a, const char b) {
        const long long int left = fallback::std::stoll(std::string(1, a), 16);
        const long long int right = fallback::std::stoll(std::string(1, b), 16);
        check_range(left, 0, 16);
        check_range(right, 0, 16);
        return static_cast<uint8_t>(left<<4) | static_cast<uint8_t>(right);
}

std::vector<uint8_t> to_binary(const std::string& hex) {
        std::vector<uint8_t> binary;
        for (auto iter = std::begin(hex); iter < std::end(hex)-1; iter+= 2) {
                binary.push_back(two_hex_chars_to_byte(*iter, *(iter+1)));
        }
        return binary;
}

void test_ip(const std::unique_ptr<ip>& ip, const ip::Version v, const std::string& src, const std::string& dst, const size_t header_length, const ip::Payload pl_type) {
        CPPUNIT_ASSERT(ip != nullptr);
        CPPUNIT_ASSERT_EQUAL(v, ip->version());
        CPPUNIT_ASSERT_EQUAL(parse_ip(src), ip->source());
        CPPUNIT_ASSERT_EQUAL(parse_ip(dst), ip->destination());
        CPPUNIT_ASSERT_EQUAL(static_cast<uint8_t>(pl_type), ip->payload_protocol());
        CPPUNIT_ASSERT_EQUAL(header_length, ip->header_length());
}

void test_ll(const std::unique_ptr<Link_layer>& ll, const size_t length, const std::string& src, const ip::Version payload_protocol, const std::string& info) {
        CPPUNIT_ASSERT(ll != nullptr);
        CPPUNIT_ASSERT_EQUAL(length, ll->header_length());
        CPPUNIT_ASSERT_EQUAL(src, binary_to_mac(ll->source()));
        CPPUNIT_ASSERT_EQUAL(static_cast<uint16_t>(payload_protocol), ll->payload_protocol());
        CPPUNIT_ASSERT_EQUAL(info, ll->get_info());
}

bool operator==(const Link_layer& lhs, const Link_layer& rhs) {
        return lhs.header_length() == rhs.header_length()
                && lhs.payload_protocol() == rhs.payload_protocol()
                && lhs.get_info() == rhs.get_info();
}

bool operator==(const ip& lhs, const ip& rhs) {
        return lhs.version() == rhs.version()
                && lhs.destination() == rhs.destination()
                && lhs.payload_protocol() == rhs.payload_protocol()
                && lhs.source() == rhs.source();
}

bool operator<(IP_address const & lhs, IP_address const & rhs) {
        return lhs.with_subnet() < rhs.with_subnet();
}

std::vector<std::string> get_ip_neigh_output(File_descriptor const ip_neigh_output) {
        std::vector<std::string> const cmd{get_path("ip"), "neigh"};
        pid_t const pid = spawn(cmd, "/dev/null", ip_neigh_output);
        const uint8_t status = wait_until_pid_exits(pid);
        CPPUNIT_ASSERT_EQUAL(static_cast<uint8_t>(0), status);
        return ip_neigh_output.get_content();
}

Iface_Ips get_iface_ips(std::vector<std::string> const ip_neigh_content) {
        auto const is_ip_not_stale = [] (std::string const & line) {
                return line.find("STALE") == std::string::npos;
        };

        auto const create_iface_ip = [] (std::string const & line) {
                auto const token = split(line, ' ');
                return std::make_tuple(token.at(2), parse_ip(token.at(0)));
        };

        std::vector<std::string> not_stale_lines;
        std::copy_if(std::begin(ip_neigh_content), std::end(ip_neigh_content), std::back_inserter(not_stale_lines), is_ip_not_stale);

        Iface_Ips iface_ip(not_stale_lines.size());
        std::transform(std::begin(not_stale_lines), std::end(not_stale_lines), std::begin(iface_ip), create_iface_ip);

        return iface_ip;
}

