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
  license : 'GPL',
  default_options : ['cpp_std=c++20', 'warning_level=3']
)

# enable all warnings found
subdir('compiler_warnings')
subdir('src')

cppunit_dep = dependency('cppunit', required: false)
if cppunit_dep.found()
  subdir('tests')
endif
