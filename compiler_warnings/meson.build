# Copyright (C) 2020  Lutz Reinhardt
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

# enable all warnings found
warnings = [
  # useful warning to improve c++ code
  '-Weffc++',
  '-Wformat',
  '-Wnull-dereference',
  '-Wswitch-default',
  '-Wswitch-enum',
  '-Wsync-nand',
  '-Wunused-const-variable',
  '-Wstringop-truncation',
  '-Wsuggest-attribute=pure',
  '-Wsuggest-attribute=const',
  '-Wsuggest-attribute=noreturn',
  '-Wsuggest-attribute=format',
  '-Wsuggest-attribute=cold',
  '-Wsuggest-attribute=malloc',
  '-Wsuggest-final-types',
  '-Wsuggest-final-methods',
  '-Wsuggest-override',
  '-Walloc-zero',
  '-Walloca',
  '-Warith-conversion',
  '-Wduplicated-branches',
  '-Wduplicated-cond',
  '-Wtrampolines',
  '-Wfloat-equal',
  '-Wshadow',
  '-Wundef',
  '-Wunused-macros',
  '-Wcast-qual',
  '-Wcast-align',
  '-Wconditionally-supported',
  '-Wzero-as-null-pointer-constant',
  '-Wuseless-cast',
  '-Wextra-semi',
  '-Wsign-conversion',
  '-Wlogical-op',
  '-Wno-aggressive-loop-optimizations',
  # useful to rethink public/private interfaces of cpp files
  # prints in c++ no warnings for templates, inline functions and functions in
  # anonymous namespace
  '-Wmissing-declarations',
  '-Wopenmp-simd',
  '-Wpacked',
  '-Wredundant-decls',
  '-Winline',
  '-Wvla',
  '-Wdisabled-optimization',
  '-Whsa',
  # warnings from clang
  # enable everything and then switch not so useful warnings off
  '-Weverything',
  '-Wno-padded',
  '-Wno-weak-vtables',
  '-Wno-global-constructors',
  '-Wno-c++98-compat',
  '-Wno-c++98-compat-bind-to-temporary-copy',
  '-Wno-exit-time-destructors',
  '-Wno-covered-switch-default',
  '-Wno-disabled-macro-expansion'
]

compiler = meson.get_compiler('cpp')
foreach w: warnings
  if (compiler.has_argument(w))
    add_global_arguments(w, language: 'cpp')
  endif
endforeach

