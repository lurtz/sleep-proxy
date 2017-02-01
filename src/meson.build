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

sleep_proxy_sources = files('pcap_wrapper.cpp', 'ethernet.cpp', 'ip.cpp', 'scope_guard.cpp', 'ip_utils.cpp', 'socket.cpp', 'args.cpp', 'to_string.cpp', 'libsleep_proxy.cpp', 'spawn_process.cpp', 'int_utils.cpp', 'wol.cpp', 'packet_parser.cpp', 'log.cpp', 'ip_address.cpp', 'file_descriptor.cpp', 'duplicate_address_watcher.cpp', 'wol_watcher.cpp')

pcap_dep = meson.get_compiler('cpp').find_library('pcap')
thread_dep = dependency('threads')

sleep_proxy_include = include_directories('.')
sleep_proxy_lib = shared_library(
        'sleep_proxy_lib',
         sleep_proxy_sources,
         dependencies : [pcap_dep, thread_dep],
         include_directories : sleep_proxy_include)
sleep_proxy_dep = declare_dependency(
        link_with : sleep_proxy_lib,
        include_directories : sleep_proxy_include)

programs = ['emulateHost', 'waker', 'sniffer']

foreach pr : programs
        executable(pr, '@0@.cpp'.format(pr), dependencies : [sleep_proxy_dep])
endforeach

watchHost = executable('watchHost', 'watchHost.cpp', dependencies : [sleep_proxy_dep, thread_dep])
