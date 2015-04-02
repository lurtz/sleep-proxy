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

FIND_PACKAGE(CPPUNIT)
FIND_PACKAGE(VALGRIND)

if (NOT CPPUNIT_FOUND)
        message(STATUS "disabling tests")
        return()
endif (NOT CPPUNIT_FOUND)

message(STATUS "enabling tests")

if (VALGRIND_PROGRAM)
        message(STATUS "enabling valgrind tests")
endif (VALGRIND_PROGRAM)

enable_testing()

function(make_test name)
        add_executable(${name} ${name}.cpp)
        target_link_libraries(${name} ${CPPUNIT_LIBRARIES} ${ARGV1} ${ARGV2})
        add_test(${name} ${name})
        if (VALGRIND_PROGRAM)
                add_test(${name}-valgrind ${VALGRIND_PROGRAM} --error-exitcode=9001 ./${name})
        endif (VALGRIND_PROGRAM)
endfunction(make_test)

include_directories("${PROJECT_SOURCE_DIR}/src")

file(COPY "${PROJECT_SOURCE_DIR}/tests/watchhosts" DESTINATION "${PROJECT_BINARY_DIR}/tests")
file(COPY "${PROJECT_SOURCE_DIR}/tests/watchhosts-empty" DESTINATION "${PROJECT_BINARY_DIR}/tests")

add_library(packet_test_utils SHARED packet_test_utils.cpp)
target_link_libraries(packet_test_utils sleep-proxy)

make_test(container_tests)
make_test(int_utils_test sleep-proxy)
make_test(to_string_test sleep-proxy)
make_test(ip_utils_test sleep-proxy)
make_test(scope_guard_test sleep-proxy)
make_test(args_test sleep-proxy)
make_test(spawn_process_test sleep-proxy)
make_test(log_test sleep-proxy)
make_test(libsleep_proxy_test sleep-proxy)
make_test(ethernet_test packet_test_utils)
make_test(wol_test sleep-proxy)
make_test(duplicate_address_watcher_test sleep-proxy packet_test_utils)
make_test(ip_address_test sleep-proxy)
make_test(packet_parser_test packet_test_utils)
make_test(ip_test packet_test_utils)
make_test(socket_test sleep-proxy)
make_test(file_descriptor_test sleep-proxy)

