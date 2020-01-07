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

subdir('packet_test_utils')

test_main_lib = static_library(
        'test_main_lib',
        'main.cpp',
        dependencies: cppunit_dep)
test_main_dep = declare_dependency(
        link_with : test_main_lib,
        dependencies : cppunit_dep)

configure_file(input : 'watchhosts', output : 'watchhosts', copy : true)
configure_file(input : 'watchhosts-empty', output : 'watchhosts-empty', copy : true)

tests = ['container_tests','int_utils_test','to_string_test','ip_utils_test','scope_guard_test','args_test','spawn_process_test','log_test','libsleep_proxy_test','ethernet_test','wol_test','duplicate_address_watcher_test','ip_address_test','packet_parser_test','ip_test','socket_test','file_descriptor_test','wol_watcher_test']

valgrind = find_program('valgrind', required : false)

foreach te : tests
        le_test = executable(te, '@0@.cpp'.format(te), dependencies : [packet_test_utils_dep, test_main_dep])
        test(te, le_test, timeout : 50)
        if valgrind.found()
                test('@0@_valgrind'.format(te), valgrind, args : ['--leak-check=yes', '--suppressions=@0@/valgrind.supp'.format(meson.current_source_dir()), '--error-exitcode=9001', 'tests/@0@'.format(te)], timeout : 50)
        endif
endforeach
