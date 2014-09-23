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

#include "int_utils.h"
#include <cerrno>
#include <cstdlib>
#include "to_string.h"

namespace fallback {
namespace std {
const ::std::string numbers{"-0123456789abcdefABCDEF"};

long long int stoll(const ::std::string& s, const int base) {
        if (s.size() == 0 || !contains_only_valid_characters(s, numbers)) {
                throw ::std::invalid_argument("strtoll(): cannot convert string: " + s);
        }
        auto errno_save = errno;
        errno = 0;
        auto ret_val = strtoll(s.c_str(), nullptr, base);
        switch (errno) {
                case 0: break;
                case ERANGE:
                        throw ::std::out_of_range("strtoll() failed to convert:" + s);
                        break;
                default:
                        throw ::std::invalid_argument("strtoll() failed to convert: " + s);
                        break;
        }
        errno = errno_save;
        return ret_val;
}

unsigned long long int stoull(const ::std::string& s, const int base) {
        if (s.size() == 0 || !contains_only_valid_characters(s, numbers)) {
                throw ::std::invalid_argument("strtoull(): cannot convert string: " + s);
        }
        auto errno_save = errno;
        errno = 0;
        auto ret_val = strtoull(s.c_str(), nullptr, base);
        if (s.at(0) == '-') {
                errno = ERANGE;
        }
        switch (errno) {
                case 0: break;
                case ERANGE:
                        throw ::std::out_of_range("strtoull() failed to convert:" + s);
                        break;
                default:
                        throw ::std::invalid_argument("strtoull() failed to convert: " + s);
                        break;
        }
        errno = errno_save;
        return ret_val;
}
}
}

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

std::string one_byte_to_two_hex_chars(const uint8_t b) noexcept {
        char val[3] = {0};
        snprintf(val, sizeof(val), "%x%x", b >> 4, b & 0xf);
        return val;
}

std::string to_hex(const std::vector<uint8_t>& bin) noexcept {
        std::string ret_val;
        for (const auto& c : bin) {
                ret_val += one_byte_to_two_hex_chars(c);
        }
        return ret_val;
}

