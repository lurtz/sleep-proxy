# Copyright (C) 2014  Lutz Reinhardt
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

find_package(PCAP REQUIRED)
find_package(Threads REQUIRED)

add_library(sleep-proxy SHARED sleep-proxy/pcap_wrapper.cpp sleep-proxy/ethernet.cpp sleep-proxy/ip.cpp sleep-proxy/scope_guard.cpp sleep-proxy/ip_utils.cpp sleep-proxy/socket.cpp sleep-proxy/args.cpp sleep-proxy/to_string.cpp sleep-proxy/libsleep_proxy.cpp sleep-proxy/spawn_process.cpp sleep-proxy/int_utils.cpp sleep-proxy/wol.cpp sleep-proxy/packet_parser.cpp sleep-proxy/log.cpp sleep-proxy/ip_address.cpp sleep-proxy/file_descriptor.cpp sleep-proxy/duplicate_address_watcher.cpp sleep-proxy/wol_watcher.cpp)
target_link_libraries(sleep-proxy PUBLIC pcap::pcap Threads::Threads)
target_include_directories(sleep-proxy PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

set(main_programs emulateHost watchHost waker sniffer)

foreach(program ${main_programs})
        message(STATUS "adding program: ${program}")
        add_executable(${program} ${program}.cpp)
        target_link_libraries(${program} sleep-proxy)
endforeach(program)

INSTALL(TARGETS sleep-proxy ${main_programs}
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin
)

