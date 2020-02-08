#!/bin/sh

find * -name "*.h" -or -name "*.cpp" | xargs clang-tidy -p .

exit 0
