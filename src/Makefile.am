## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003 Simon Josefsson.
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

AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_srcdir)/db -I../lib

bin_PROGRAMS = shishi shisa

shishi_SOURCES = shishi.c gettext.h
shishi_LDADD = @LIBGCRYPT_LIBS@ @CRYPTO_LIBS@ \
	@LTLIBINTL@ ../gl/libfoo.la @LIBTASN1_LIBS@ @LIBGNUTLS_LIBS@ \
	../lib/libshishi.la

BUILT_SOURCES = shisa_cmd.c shisa_cmd.h
shisa_SOURCES = shisa.c gettext.h shisa.ggo $(BUILT_SOURCES)
shisa_LDADD = ../db/libshisa.la

$(BUILT_SOURCES): shisa.ggo
	gengetopt --unamed-opts --input $< --file-name shisa_cmd
	perl -pi -e 's/\[FILES\]/\[REALM \[CLIENT\]\]/g' shisa_cmd.c

sbin_PROGRAMS = shishid
shishid_SOURCES = shishid.c
shishid_LDADD = @LIBGCRYPT_LIBS@ @CRYPTO_LIBS@ \
	@LTLIBINTL@ ../gl/libfoo.la @LIBTASN1_LIBS@ @LIBGNUTLS_LIBS@ \
	../lib/libshishi.la

localedir = $(datadir)/locale

DEFS = -DLOCALEDIR=\"$(localedir)\" \
	-DSYSTEMCFGFILE=\"$(sysconfdir)/shishi.conf\" \
	-DKDCKEYFILE=\"$(sysconfdir)/shishid.keys\" \
	-DSKELCFGFILE=\"$(pkgdatadir)/shishi.skel\" \
	@DEFS@

indent:
	indent $(SOURCES)
