#!/bin/sh
set -x
AUTOMAKE=${AUTOMAKE:-automake}; export AUTOMAKE
ACLOCAL=${ACLOCAL:-aclocal}; export ACLOCAL
AUTOCONF=${AUTOCONF:-autoconf}; export AUTOCONF
AUTOHEADER=${AUTOHEADER:-autoheader}; export AUTOHEADER
LIBTOOLIZE=${LIBTOOLIZE:-libtoolize}; export LIBTOOLIZE
GETTEXTIZE=${GETTEXTIZE:-gettextize}; export GETTEXTIZE

cd argp &&
rm -vf config.cache &&
rm -rvf autom4te.cache &&
$ACLOCAL &&
$AUTOCONF &&
$AUTOMAKE --add-missing &&
$AUTOHEADER &&
cd .. &&
#cd crypto &&
#rm -vf config.cache &&
#rm -rvf autom4te.cache &&
#./autogen.sh &&
#cd .. &&
$GETTEXTIZE --intl --force &&
rm -fv `find . -name \*~` &&
rm -vf config.cache &&
rm -vrf autom4te.cache &&
$ACLOCAL -I m4 -I crypto/src -I asn1/src &&
$LIBTOOLIZE --force --automake &&
$ACLOCAL -I m4 -I crypto/src -I asn1/src &&
$AUTOCONF &&
$AUTOMAKE --gnits --add-missing &&
$AUTOHEADER &&
: 'You can now run CFLAGS=-g ./configure --enable-maintainer-mode --disable-shared and then make.'
