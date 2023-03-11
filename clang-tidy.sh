#!/bin/sh

find * -name "*.h" -or -name "*.cpp" | xargs clang-tidy -p build

exit 0
