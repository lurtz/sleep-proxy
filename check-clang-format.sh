#!/bin/bash

./clang-format.sh

MSG="The following files have been modified:"
dirty=$(git ls-files --modified)

if [[ $dirty ]]; then
	echo $MSG
	echo $dirty
	exit 1
fi
