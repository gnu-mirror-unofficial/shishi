#!/bin/sh
#
# Check whether Docbook mode allows gdoc to produce
# valid XML as output.
#
# Copyright (C) 2014 Mats Erik Andersson
#
# This file is part of Shishi.
#
# Shishi is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# Shishi is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Shishi; if not, see http://www.gnu.org/licenses or write
# to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
# Floor, Boston, MA 02110-1301, USA.

set -eu

GDOC=${GDOC:-gdoc}
XMLLINT=${XMLLINT:-xmllint}
XSLTPROC=${XSLTPROC:-xsltproc}

if test -z "$(command -v $XMLLINT)"; then
    echo >&2 'Not able to access xmllint.'
    exit 77
fi

#if test -z "$(command -v $XSLTPROC)"; then
#    echo >&2 'Not able to access xsltproc.'
#    exit 77
#fi

if test -z "$(command -v $GDOC)"; then
    GDOC=./doc/gdoc
    if test ! -x $GDOC; then
	GDOC=../doc/gdoc
	if test ! -x $GDOC; then
	    echo >&2 'Not able to find an executable gdoc.'
	    exit 77
	fi
    fi
fi

while test $# -gt 0; do
    file=$1
    shift
    printf "%-20s" ">>> $file"

    FLIST=$($GDOC -listfunc $file 2>/dev/null)
    for funcname in $FLIST; do
	$GDOC -docbook -dtd -function $funcname $file |
	$XMLLINT -noout -valid -
    done && echo ' OK'
done
