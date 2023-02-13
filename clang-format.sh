#!/bin/sh

find * -name "*.h" -or -name "*.cpp" | xargs clang-format -style file -i

exit 0
