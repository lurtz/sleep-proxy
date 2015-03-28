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

find_package (Threads)
add_library(sleep-proxy SHARED pcap_wrapper.cpp ethernet.cpp ip.cpp scope_guard.cpp ip_utils.cpp socket.cpp args.cpp to_string.cpp libsleep_proxy.cpp spawn_process.cpp int_utils.cpp wol.cpp packet_parser.cpp log.cpp ip_address.cpp file_descriptor.cpp duplicate_address_watcher.cpp)
target_link_libraries(sleep-proxy ${PCAP_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

add_executable(emulateHost emulateHost.cpp)
target_link_libraries(emulateHost sleep-proxy)

add_executable(watchHost watchHost.cpp)
target_link_libraries(watchHost sleep-proxy)

add_executable(waker waker.cpp)
target_link_libraries(waker sleep-proxy)

add_executable(sniffer sniffer.cpp)
target_link_libraries(sniffer sleep-proxy)

INSTALL(TARGETS sleep-proxy emulateHost watchHost waker sniffer
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin
)
