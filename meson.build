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

project('sleep proxy', 'cpp',
  version : '0.0.1',
  license : 'GPL')
add_global_arguments(language : 'cpp')

subdir('src')

cppunit_dep = dependency('cppunit', required: false)
if cppunit_dep.found()
  subdir('tests')
endif

pkg_mod = import('pkgconfig')
pkg_mod.generate(libraries : sleep_proxy_lib,
                 version : '0.0.1',
                 name : 'libsleep_proxy',
                 filebase : 'sleep_proxy',
                 description : 'A Library to barnicate your foos.')

