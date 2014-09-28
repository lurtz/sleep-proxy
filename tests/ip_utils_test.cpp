// Copyright (C) 2014  Lutz Reinhardt
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#include "main.h"
#include <string>
#include <arpa/inet.h>

#include "ip_utils.h"
#include "int_utils.h"
#include "split.h"
#include "ip_address.h"

class Ip_utils_test : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE( Ip_utils_test );
        CPPUNIT_TEST( test_validate_iface );
        CPPUNIT_TEST( test_validate_mac );
        CPPUNIT_TEST( test_get_pure_ip );
        CPPUNIT_TEST( test_get_af );
        CPPUNIT_TEST( test_parse_items );
        CPPUNIT_TEST( test_sanitize_ip );
        CPPUNIT_TEST( test_parse_ip );
        CPPUNIT_TEST_SUITE_END();
        public:
        void setUp() {}

        void tearDown() {}

        void test_validate_iface() {
                CPPUNIT_ASSERT_EQUAL(std::string("eth0"), validate_iface("eth0"));
                CPPUNIT_ASSERT_EQUAL(std::string("wlan1"), validate_iface("wlan1"));
                CPPUNIT_ASSERT_EQUAL(std::string("br2"), validate_iface("br2"));
                CPPUNIT_ASSERT_EQUAL(std::string("eth0.0"), validate_iface("eth0.0"));
                CPPUNIT_ASSERT_THROW(validate_iface("eth0;"), std::runtime_error);
                CPPUNIT_ASSERT_EQUAL(std::string("lo"), validate_iface("lo"));
                CPPUNIT_ASSERT_THROW(validate_iface("lo\""), std::runtime_error);
                CPPUNIT_ASSERT_EQUAL(std::string(""), validate_iface(""));

        }

        void test_validate_mac() {
                CPPUNIT_ASSERT_EQUAL(std::string("01:23:45:67:89:ab"), validate_mac("01:23:45:67:89:AB"));
                CPPUNIT_ASSERT_EQUAL(std::string("01:23:45:67:89:ab"), validate_mac("01:23:45:67:89:ab"));
                CPPUNIT_ASSERT_THROW(validate_mac("lo\""), std::runtime_error);
                CPPUNIT_ASSERT_THROW(validate_mac("01:23:45:67:89:AAB"), std::runtime_error);
                CPPUNIT_ASSERT_THROW(validate_mac("01:23:45:67:89"), std::runtime_error);
                CPPUNIT_ASSERT_THROW(validate_mac("01:23:45:67:89:"), std::runtime_error);
        }

        void test_get_pure_ip() {
                CPPUNIT_ASSERT_EQUAL(std::string("fe80::123"), get_pure_ip("fe80::123/64%lo"));
                CPPUNIT_ASSERT_EQUAL(std::string("fe80::123"), get_pure_ip("fe80::123/64"));
                CPPUNIT_ASSERT_EQUAL(std::string("fe80::123"), get_pure_ip("fe80::123"));
                CPPUNIT_ASSERT_EQUAL(std::string("192.168.1.1"), get_pure_ip("192.168.1.1/24"));
                CPPUNIT_ASSERT_EQUAL(std::string("blabla"), get_pure_ip("blabla//rumsbums"));
                CPPUNIT_ASSERT_EQUAL(std::string("blabla"), get_pure_ip("blabla/%rumsbums"));
                CPPUNIT_ASSERT_EQUAL(std::string("blabla"), get_pure_ip("blabla/%rumsbums/abcabd"));
        }

        void test_get_af() {
                CPPUNIT_ASSERT_EQUAL(AF_INET, getAF("192.168.1.1"));
                CPPUNIT_ASSERT_EQUAL(AF_INET, getAF("10.0.0.1"));
                CPPUNIT_ASSERT_EQUAL(AF_INET6, getAF("::1"));
                CPPUNIT_ASSERT_EQUAL(AF_INET6, getAF("fe80::123"));
                CPPUNIT_ASSERT_EQUAL(AF_INET6, getAF("2001::123"));
                CPPUNIT_ASSERT_THROW(getAF("abc"), std::runtime_error);
                CPPUNIT_ASSERT_THROW(getAF("2001::123::123"), std::runtime_error);
        }
        void test_parse_items() {
                std::vector<std::string> strings{"1","2","3","4"};
                std::vector<int> ints{1,2,3,4};
                CPPUNIT_ASSERT(ints == parse_items(split("1,2,3,4", ','), str_to_integral<int>));
                CPPUNIT_ASSERT(ints == parse_items(strings, str_to_integral<int>));
                auto lamb = [](std::string s){return s;};
                CPPUNIT_ASSERT(strings == parse_items(strings, lamb));
                CPPUNIT_ASSERT(std::vector<int>() == parse_items(std::vector<std::string>(), str_to_integral<int>));
        }

        void test_sanitize_ip() {
                CPPUNIT_ASSERT_EQUAL(std::string("192.168.1.1/24"), sanitize_ip("192.168.1.1/24"));
                CPPUNIT_ASSERT_EQUAL(std::string("192.168.1.1/24"), sanitize_ip("192.168.1.1"));
                CPPUNIT_ASSERT_EQUAL(std::string("192.168.1.1/16"), sanitize_ip("192.168.1.1/16"));
                CPPUNIT_ASSERT_EQUAL(std::string("fe80::12/64"), sanitize_ip("fe80::12"));
                CPPUNIT_ASSERT_EQUAL(std::string("fe80::12/64"), sanitize_ip("fe80::12%lo"));
                CPPUNIT_ASSERT_EQUAL(std::string("fe80::12/64"), sanitize_ip("fe80::12/64%lo"));
                CPPUNIT_ASSERT_THROW(sanitize_ip("bla/bla/"), std::invalid_argument);
                CPPUNIT_ASSERT_THROW(sanitize_ip("fe80::123::123"), std::runtime_error);
                CPPUNIT_ASSERT_THROW(sanitize_ip("10"), std::runtime_error);
                CPPUNIT_ASSERT_THROW(sanitize_ip("fe80::123/200"), std::invalid_argument);
                CPPUNIT_ASSERT_THROW(sanitize_ip("10.0.0.1/200"), std::invalid_argument);
        }

        void compare_ip(const std::string& full_ip, const int family, const std::string& ip, const uint8_t subnet) {
                const IP_address ipa = parse_ip(full_ip);
                CPPUNIT_ASSERT_EQUAL(family, ipa.family);
                CPPUNIT_ASSERT_EQUAL(ip, ipa.pure());
                CPPUNIT_ASSERT_EQUAL(static_cast<uint8_t>(subnet), ipa.subnet);
                CPPUNIT_ASSERT_EQUAL(ip + "/" + to_string(subnet), ipa.with_subnet());
        }

        void test_parse_ip() {
                compare_ip("192.168.1.1/24", AF_INET, "192.168.1.1", 24);
                compare_ip("192.168.1.1", AF_INET, "192.168.1.1", 24);
                compare_ip("192.168.1.1/16", AF_INET, "192.168.1.1", 16);
                compare_ip("fe80::12", AF_INET6, "fe80::12", 64);
                compare_ip("fe80::12%lo", AF_INET6, "fe80::12", 64);
                compare_ip("fe80::12/34%lo", AF_INET6, "fe80::12", 34);
                compare_ip("::1", AF_INET6, "::1", 128);
                CPPUNIT_ASSERT_THROW(parse_ip("bla/bla/"), std::invalid_argument);
                CPPUNIT_ASSERT_THROW(parse_ip("fe80::123::123"), std::runtime_error);
                CPPUNIT_ASSERT_THROW(parse_ip("10"), std::runtime_error);
                CPPUNIT_ASSERT_THROW(parse_ip("fe80::123/200"), std::invalid_argument);
                CPPUNIT_ASSERT_THROW(parse_ip("10.0.0.1/200"), std::invalid_argument);
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION( Ip_utils_test );

