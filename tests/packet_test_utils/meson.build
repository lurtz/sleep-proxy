# Copyright (C) 2017  Lutz Reinhardt
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

cppunit_dep = dependency('cppunit')

packet_test_utils_include = include_directories('include')
packet_test_utils_lib = shared_library(
        'packet_test_utils_lib',
        'packet_test_utils.cpp',
        dependencies : [sleep_proxy_dep, cppunit_dep],
        include_directories : packet_test_utils_include)
packet_test_utils_dep = declare_dependency(
        link_with : packet_test_utils_lib,
        include_directories : packet_test_utils_include,
        dependencies : [sleep_proxy_dep, cppunit_dep, thread_dep])


