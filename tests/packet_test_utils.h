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

#pragma once

#include <memory>
#include <vector>
#include <../src/ip.h>
#include <../src/ethernet.h>


std::vector<uint8_t> to_binary(const std::string& hex);

void test_ll(const std::unique_ptr<Link_layer>& ll, const size_t length, const ip::Version payload_protocol, const std::string& info);

void test_source(const std::unique_ptr<Link_layer>& ll, const std::string& src);

void test_ethernet(const std::unique_ptr<Link_layer>& ll, const std::string& src, const std::string& dst);

void test_ip(const std::unique_ptr<ip>& ip, const ip::Version v, const std::string& src, const std::string& dst, const size_t header_length, const ip::Payload pl_type);

bool operator==(const Link_layer& lhs, const Link_layer& rhs);

bool operator==(const ip& lhs, const ip& rhs);

