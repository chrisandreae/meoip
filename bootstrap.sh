#!/bin/sh

AUTOCONF_VERSION=2.59
AUTOMAKE_VERSION=1.9
export AUTOCONF_VERSION AUTOMAKE_VERSION

run ()
{
	echo "running: $*"
	eval $*

	if test $? != 0; then
		echo "error while running '$*'"
		exit 1
	fi
}

run aclocal
#run libtoolize -f
run autoheader
run autoconf
run automake -a


