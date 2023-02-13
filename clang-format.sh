#!/bin/sh

find * -name "*.h" -or -name "*.cpp" | xargs clang-format -style file -i

MSG="The following files have been modified:"
dirty=$(git ls-files --modified)

if [[ $dirty ]]; then
	echo $MSG
	echo $dirty
	exit 1
fi

exit 0
