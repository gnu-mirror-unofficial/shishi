## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008 Simon Josefsson.
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

EXTRA_DIST = shisa.sh shishi.supp keytab1.bin ccache1.bin

AM_CFLAGS = $(WARN_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_builddir)/gl \
	-I$(top_srcdir)/lib -I../lib
AM_LDFLAGS = -no-install
LDADD = @LTLIBINTL@ ../gl/libgnu.la @LTLIBTASN1@ @LTLIBGNUTLS@ \
	../lib/libshishi.la libutils.la

noinst_LTLIBRARIES = libutils.la
libutils_la_SOURCES = utils.h utils.c

check_PROGRAMS = authenticator crypto gztime priv safe ticketset	\
	crypto-ctx low-crypto rijndael key keytab ccache nonce		\
	passwdpromptcb
TESTS = $(check_PROGRAMS)

TESTS_ENVIRONMENT = \
	KEYTAB1=$(srcdir)/keytab1.bin	\
	CCACHE1=$(srcdir)/ccache1.bin	\
	$(VALGRIND)
