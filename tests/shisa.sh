#!/bin/sh
# Copyright (C) 2003 Simon Josefsson.
#
# This file is part of Shishi.
#
# Shishi is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# Shishi is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Shishi; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.

SHISA=$PWD/../src/shisa
DBDIR=shisa.db.tmp.$$

OUT=$DBDIR/out
ERR=$DBDIR/err
CONF=$DBDIR/conf

if test -n "$VERBOSE"; then
    set -x
fi

mkdir $DBDIR
if test ! -d $DBDIR; then
	echo Cannot create $DBDIR
	exit 1
fi

trap "rm -rf $DBDIR" EXIT

echo "db file $DBDIR" > $CONF
if test ! -f $CONF; then
	echo Cannot create $CONF
	exit 1
fi

if test ! -f $SHISA; then
    echo Cannot find $SHISA
    exit 1
fi

echo Dump empty database.
out=`$SHISA -c $CONF -d`
if test $? != 0; then
    echo rc $?
    exit 1
fi
expectout=""
if test "$out" != "$expectout"; then
    echo expected: $expectout >&2
    echo got: $out >&2
    exit 1
fi

echo Add realm.
out=`$SHISA -c $CONF -a TESTREALM`
if test $? != 0; then
    echo rc $?
    exit 1
fi
expectout="Adding realm \`TESTREALM'...
Adding realm \`TESTREALM'...done"
if test "$out" != "$expectout"; then
    echo expected: $expectout >&2
    echo got: $out >&2
    exit 1
fi

echo List database.
out=`$SHISA -c $CONF -l`
if test $? != 0; then
    echo rc $?
    exit 1
fi
expectout="TESTREALM"
if test "$out" != "$expectout"; then
    echo expected: $expectout >&2
    echo got: $out >&2
    exit 1
fi

echo Add realm.
out=`$SHISA -c $CONF -a TESTREALM2`
if test $? != 0; then
    echo rc $?
    exit 1
fi
expectout="Adding realm \`TESTREALM2'...
Adding realm \`TESTREALM2'...done"
if test "$out" != "$expectout"; then
    echo expected: $expectout >&2
    echo got: $out >&2
    exit 1
fi

echo Dump database.
out=`$SHISA -c $CONF -d`
if test $? != 0; then
    echo rc $?
    exit 1
fi
expectout="TESTREALM
TESTREALM2"
if test "$out" != "$expectout"; then
    echo expected: $expectout >&2
    echo got: $out >&2
    exit 1
fi

echo Remove realm.
out=`$SHISA -c $CONF -r TESTREALM2`
if test $? != 0; then
    echo rc $?
    exit 1
fi
expectout="Removing realm \`TESTREALM2'...
Removing realm \`TESTREALM2'...done"
if test "$out" != "$expectout"; then
    echo expected: $expectout >&2
    echo got: $out >&2
    exit 1
fi

echo Dump database.
out=`$SHISA -c $CONF -d`
if test $? != 0; then
    echo rc $?
    exit 1
fi
expectout="TESTREALM"
if test "$out" != "$expectout"; then
    echo expected: $expectout >&2
    echo got: $out >&2
    exit 1
fi

echo Add principal.
out=`$SHISA -c $CONF -a TESTREALM test/principal`
if test $? != 0; then
    echo rc $?
    exit 1
fi
expectout="Adding principal \`test/principal@TESTREALM'...
Adding principal \`test/principal@TESTREALM'...done"
if test "$out" != "$expectout"; then
    echo expected: $expectout >&2
    echo got: $out >&2
    exit 1
fi

echo Dump database.
out=`$SHISA -c $CONF -d`
if test $? != 0; then
    echo rc $?
    exit 1
fi
expectout="TESTREALM
	test/principal
		Account is enabled.
		Current key version 0 (0x0).
		Key 0 (0x0).
			Etype aes256-cts-hmac-sha1-96 (0x12, 18)."
if test "$out" != "$expectout"; then
    echo expected: $expectout >&2
    echo got: $out >&2
    exit 1
fi

echo Add second principal.
out=`$SHISA -c $CONF -a TESTREALM test/principal2`
if test $? != 0; then
    echo rc $?
    exit 1
fi
expectout="Adding principal \`test/principal2@TESTREALM'...
Adding principal \`test/principal2@TESTREALM'...done"
if test "$out" != "$expectout"; then
    echo expected: $expectout >&2
    echo got: $out >&2
    exit 1
fi

echo Dump database.
out=`$SHISA -c $CONF -d`
if test $? != 0; then
    echo rc $?
    exit 1
fi
expectout="TESTREALM
	test/principal
		Account is enabled.
		Current key version 0 (0x0).
		Key 0 (0x0).
			Etype aes256-cts-hmac-sha1-96 (0x12, 18).
	test/principal2
		Account is enabled.
		Current key version 0 (0x0).
		Key 0 (0x0).
			Etype aes256-cts-hmac-sha1-96 (0x12, 18)."
if test "$out" != "$expectout"; then
    echo expected: $expectout >&2
    echo got: $out >&2
    exit 1
fi

echo Add third principal.
out=`$SHISA -c $CONF -a TESTREALM test/principal3`
if test $? != 0; then
    echo rc $?
    exit 1
fi
expectout="Adding principal \`test/principal3@TESTREALM'...
Adding principal \`test/principal3@TESTREALM'...done"
if test "$out" != "$expectout"; then
    echo expected: $expectout >&2
    echo got: $out >&2
    exit 1
fi

echo Remove second principal.
out=`$SHISA -c $CONF -r TESTREALM test/principal2`
if test $? != 0; then
    echo rc $?
    exit 1
fi
expectout="Removing principal \`test/principal2@TESTREALM'...
Removing principal \`test/principal2@TESTREALM'...done"
if test "$out" != "$expectout"; then
    echo expected: $expectout >&2
    echo got: $out >&2
    exit 1
fi

echo Dump database.
out=`$SHISA -c $CONF -d`
if test $? != 0; then
    echo rc $?
    exit 1
fi
expectout="TESTREALM
	test/principal
		Account is enabled.
		Current key version 0 (0x0).
		Key 0 (0x0).
			Etype aes256-cts-hmac-sha1-96 (0x12, 18).
	test/principal3
		Account is enabled.
		Current key version 0 (0x0).
		Key 0 (0x0).
			Etype aes256-cts-hmac-sha1-96 (0x12, 18)."
if test "$out" != "$expectout"; then
    echo expected: $expectout >&2
    echo got: $out >&2
    exit 1
fi

echo Tring to remove entire realm.
out=`$SHISA -c $CONF -r TESTREALM`
if test $? != 1; then
    echo rc $?
    exit 1
fi

echo Dump database.
out=`$SHISA -c $CONF -d`
if test $? != 0; then
    echo rc $?
    exit 1
fi
expectout="TESTREALM
	test/principal
		Account is enabled.
		Current key version 0 (0x0).
		Key 0 (0x0).
			Etype aes256-cts-hmac-sha1-96 (0x12, 18).
	test/principal3
		Account is enabled.
		Current key version 0 (0x0).
		Key 0 (0x0).
			Etype aes256-cts-hmac-sha1-96 (0x12, 18)."
if test "$out" != "$expectout"; then
    echo expected: $expectout >&2
    echo got: $out >&2
    exit 1
fi

echo Tests finished
exit 0
