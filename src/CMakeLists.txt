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
find_package (Threads REQUIRED)

set(sleep-proxy-files pcap_wrapper.cpp ethernet.cpp ip.cpp scope_guard.cpp ip_utils.cpp socket.cpp args.cpp to_string.cpp libsleep_proxy.cpp spawn_process.cpp int_utils.cpp wol.cpp packet_parser.cpp log.cpp ip_address.cpp file_descriptor.cpp duplicate_address_watcher.cpp wol_watcher.cpp)

add_library(sleep-proxy SHARED ${sleep-proxy-files})
target_link_libraries(sleep-proxy ${PCAP_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
target_include_directories(sleep-proxy PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

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

