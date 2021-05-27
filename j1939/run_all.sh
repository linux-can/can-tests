#!/bin/sh

set -e

for f in j1939*.sh; do
	echo "##############################################"
	pre=$(lsmod | awk '/^can_j1939/ { print $3 }')
	echo "run: $f"
	./$f "${@}"
	echo "done: $f"
	post=$(lsmod | awk '/^can_j1939/ { print $3 }')
	if [ $pre -ne $post ]; then
		echo "module usage: before start: $pre"
		echo "              after finish: $post"
		exit 1
	fi
	echo "##############################################"
done
