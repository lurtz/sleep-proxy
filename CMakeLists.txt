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

cmake_minimum_required (VERSION 2.6)
project (emulateHost)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${emulateHost_SOURCE_DIR}/cmake)
find_package(PCAP REQUIRED)
add_definitions(-std=c++11)

INCLUDE(CompilerFlags)

# Compiler setup
#set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${VALID_FLAGS}")

# testing
FIND_PACKAGE(CPPUNIT)
if (CPPUNIT_FOUND)
        enable_testing()
        FIND_PACKAGE(VALGRIND)
        add_subdirectory(tests)
endif (CPPUNIT_FOUND)

add_subdirectory(src)
