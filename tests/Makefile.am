## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004 Simon Josefsson.
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

EXTRA_DIST = utils.c shisa.sh

AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_srcdir)/lib -I../lib
AM_LDFLAGS = -no-install
LDADD = @LIBGCRYPT_LIBS@ @CRYPTO_LIBS@ \
	@LTLIBINTL@ ../gl/libgnu.la @LIBTASN1_LIBS@ @LIBGNUTLS_LIBS@ \
	../lib/libshishi.la

check_PROGRAMS = authenticator crypto gztime priv safe \
	ticketset crypto-ctx low-crypto rijndael key
TESTS = $(check_PROGRAMS)
