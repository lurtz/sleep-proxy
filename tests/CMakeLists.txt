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

message(STATUS "enabling tests")

FIND_PACKAGE(VALGRIND)

if (VALGRIND_PROGRAM)
        message(STATUS "enabling valgrind tests")
endif (VALGRIND_PROGRAM)

enable_testing()

# valgrind --leak-check=yes --show-leak-kinds=definite --gen-suppressions=yes --demangle=no --suppressions=../tests/valgrind.supp tests/spawn_process_test

function(make_test name)
        message(STATUS "adding test: " ${name})
        add_executable(${name} ${name}.cpp)
        target_link_libraries(${name} test_main ${ARGV1} ${ARGV2})
        add_test(${name} ${name})
        if (VALGRIND_PROGRAM)
                add_test(${name}_valgrind ${VALGRIND_PROGRAM} --leak-check=yes --suppressions=${CMAKE_CURRENT_SOURCE_DIR}/valgrind.supp --error-exitcode=9001 ./${name})
        endif (VALGRIND_PROGRAM)
endfunction(make_test)

file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/watchhosts" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/watchhosts-empty" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")

add_library(packet_test_utils SHARED packet_test_utils.cpp)
target_link_libraries(packet_test_utils sleep-proxy)
target_include_directories(packet_test_utils PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_library(test_main STATIC main.cpp)
target_link_libraries(test_main PUBLIC ${CPPUNIT_LIBRARIES})

make_test(container_tests sleep-proxy)
make_test(int_utils_test sleep-proxy)
make_test(to_string_test packet_test_utils)
make_test(ip_utils_test sleep-proxy)
make_test(scope_guard_test sleep-proxy)
make_test(args_test packet_test_utils)
make_test(spawn_process_test packet_test_utils)
make_test(log_test sleep-proxy)
make_test(libsleep_proxy_test sleep-proxy)
make_test(ethernet_test packet_test_utils)
make_test(wol_test sleep-proxy)
make_test(duplicate_address_watcher_test packet_test_utils)
make_test(ip_address_test sleep-proxy)
make_test(packet_parser_test packet_test_utils)
make_test(ip_test packet_test_utils)
make_test(socket_test packet_test_utils)
make_test(file_descriptor_test packet_test_utils)
make_test(wol_watcher_test packet_test_utils)

