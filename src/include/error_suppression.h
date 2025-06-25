// Copyright (C) 2025  Lutz Reinhardt
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#pragma once

// NOLINTBEGIN(clang-diagnostic-unused-macros)
// macros are used in cpp files
#ifdef __clang__
// the unsage buffer usage warning only pops up when dealing with the arguments
// of main() where it cannot be avoided
#define IGNORE_CLANG_WARNING                                                   \
  _Pragma("clang diagnostic push") _Pragma(                                    \
      "clang diagnostic ignored \"-Wunsafe-buffer-usage-in-container\"")

#define REENABLE_CLANG_WARNING _Pragma("clang diagnostic pop")
#else
#define IGNORE_CLANG_WARNING

#define REENABLE_CLANG_WARNING
#endif
// NOLINTEND(clang-diagnostic-unused-macros)
