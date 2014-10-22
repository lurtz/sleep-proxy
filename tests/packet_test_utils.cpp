#include "packet_test_utils.h"
#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/extensions/HelperMacros.h>
#include "../src/container_utils.h"
#include "../src/int_utils.h"

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

void test_ll(const std::unique_ptr<Link_layer>& ll, const size_t length, const ip::Version payload_protocol, const std::string& info) {
        CPPUNIT_ASSERT(ll != nullptr);
        CPPUNIT_ASSERT_EQUAL(length, ll->header_length());
        CPPUNIT_ASSERT_EQUAL(static_cast<uint16_t>(payload_protocol), ll->payload_protocol());
        CPPUNIT_ASSERT_EQUAL(info, ll->get_info());
}

void test_source(const std::unique_ptr<Link_layer>& ll, const std::string& src) {
        CPPUNIT_ASSERT(ll != nullptr);
        const Source_address& sa = dynamic_cast<const Source_address&>(*ll);
        CPPUNIT_ASSERT_EQUAL(src, binary_to_mac(sa.source()));
}

void test_ethernet(const std::unique_ptr<Link_layer>& ll, const std::string& src, const std::string& dst) {
        const sniff_ethernet& ether = dynamic_cast<const sniff_ethernet&>(*ll);
        CPPUNIT_ASSERT_EQUAL(dst, binary_to_mac(ether.destination()));
        test_source(ll, src);
}

