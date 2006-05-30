## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004, 2005, 2006 Simon Josefsson.
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
# along with Shishi; see the file COPYING.  If not, write to the Free
# Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.

EXTRA_DIST = utils.c shisa.sh shishi.supp keytab1.bin

AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_builddir)/gl \
	-I$(top_srcdir)/lib -I../lib
AM_LDFLAGS = -no-install
LDADD = @LTLIBINTL@ ../gl/libgnu.la @LTLIBTASN1@ @LTLIBGNUTLS@ \
	../lib/libshishi.la

check_PROGRAMS = authenticator crypto gztime priv safe \
	ticketset crypto-ctx low-crypto rijndael key keytab
TESTS = $(check_PROGRAMS)

VALGRIND=valgrind --tool=memcheck --leak-check=full --leak-resolution=high \
	--show-reachable=yes --num-callers=50 \
	--suppressions=shishi.supp
TESTS_ENVIRONMENT = \
	KEYTAB1=$(srcdir)/keytab1.bin	\
	`if $(VALGRIND) /bin/true > /dev/null 2>&1; then echo $(VALGRIND); else echo $$SHELL -c; fi`
