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

cmake_minimum_required (VERSION 2.8.12)
project (emulateHost)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${emulateHost_SOURCE_DIR}/cmake)

# Compiler setup
#set(CMAKE_BUILD_TYPE Debug)
add_definitions(-std=c++11)
INCLUDE(CompilerFlags)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${VALID_FLAGS}")

if ("${CMAKE_CXX_COMPILER}" MATCHES ".*clang.*")
        message(STATUS "clang compiler found, will use clang-format")
        set(GCF_CLANGFORMAT_STYLE "LLVM")
        add_subdirectory(git-cmake-format)
endif()

# testing
FIND_PACKAGE(CPPUNIT)
if (CPPUNIT_FOUND)
        enable_testing()
        add_subdirectory(tests)
endif (CPPUNIT_FOUND)

# source
add_subdirectory(src)

