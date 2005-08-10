## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004, 2005 Simon Josefsson.
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

AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_builddir)/gl \
	-I$(top_srcdir)/db -I../lib
localedir = $(datadir)/locale
DEFS = @DEFS@ -DLOCALEDIR=\"$(localedir)\" \
	-DSYSTEMCFGFILE=\"$(CONFDIR)/shishi.conf\"

BUILT_SOURCES = shishi_cmd.c shishi_cmd.h shisa_cmd.c shisa_cmd.h \
	shishid_cmd.c shishid_cmd.h
MAINTAINERCLEANFILES = $(BUILT_SOURCES)

bin_PROGRAMS = shishi shisa
sbin_PROGRAMS = shishid

shishi_SOURCES = shishi.c shishi.ggo shishi_cmd.h shishi_cmd.c
shishi_LDADD = ../gl/libgnu.la ../lib/libshishi.la @LTLIBINTL@
shishi_cmd.c shishi_cmd.h: shishi.ggo
	gengetopt --unamed-opts="CLIENT [SERVER]" \
		--no-handle-help --no-handle-error \
		--input $< --file-name shishi_cmd

shisa_SOURCES = shisa.c shisa.ggo shisa_cmd.h shisa_cmd.c
shisa_LDADD = ../gl/libgnu.la ../db/libshisa.la ../lib/libshishi.la @LTLIBINTL@
shisa_cmd.c shisa_cmd.h: shisa.ggo
	gengetopt --unamed-opts="REALM [PRINCIPAL]" \
		--no-handle-help --no-handle-error \
		--input $< --file-name shisa_cmd

shishid_SOURCES = shishid.c server.c kdc.h kdc.c \
	shishid.ggo shishid_cmd.h shishid_cmd.c
if STARTTLS
shishid_SOURCES += starttls.c resume.c
endif
shishid_LDADD = ../gl/libgnu.la ../lib/libshishi.la \
	../db/libshisa.la @LIBGNUTLS_LIBS@ @LTLIBINTL@
shishid_cmd.c shishid_cmd.h: shishid.ggo
	gengetopt --no-handle-help --no-handle-error \
		 --input $< --file-name shishid_cmd
