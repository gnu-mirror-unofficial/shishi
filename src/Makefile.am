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
localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" \
	-DSYSTEMCFGFILE=\"$(CONFDIR)/shishi.conf\" \
	@DEFS@

BUILT_SOURCES = shishi_cmd.c shishi_cmd.h shisa_cmd.c shisa_cmd.h \
	shishid_cmd.c shishid_cmd.h
MAINTAINERCLEANFILES = $(BUILT_SOURCES)

bin_PROGRAMS = shishi shisa
sbin_PROGRAMS = shishid

shishi_SOURCES = shishi.c shishi.ggo shishi_cmd.h shishi_cmd.c
shishi_LDADD = ../gl/libfoo.la ../lib/libshishi.la @LTLIBINTL@
shishi_cmd.c shishi_cmd.h: shishi.ggo
	gengetopt --unamed-opts --no-handle-help --no-handle-error \
		 --input $< --file-name shishi_cmd
	perl -pi -e 's/\[FILES\]/\[CLIENT \[SERVER\]\]/g' shishi_cmd.c

shisa_SOURCES = shisa.c shisa.ggo shisa_cmd.h shisa_cmd.c
shisa_LDADD = ../gl/libfoo.la ../db/libshisa.la ../lib/libshishi.la @LTLIBINTL@
shisa_cmd.c shisa_cmd.h: shisa.ggo
	gengetopt --unamed-opts --no-handle-help --no-handle-error \
		 --input $< --file-name shisa_cmd
	perl -pi -e 's/\[FILES\]/\[REALM \[PRINCIPAL\]\]/g' shisa_cmd.c

shishid_SOURCES = shishid.c server.c kdc.c \
	shishid.ggo shishid_cmd.h shishid_cmd.c
shishid_LDADD = ../gl/libfoo.la ../lib/libshishi.la ../db/libshisa.la \
	@LIBGNUTLS_LIBS@ @LTLIBINTL@
shishid_cmd.c shishid_cmd.h: shishid.ggo
	gengetopt --no-handle-help --no-handle-error \
		 --input $< --file-name shishid_cmd

# Maintainer targets

indent:
	indent $(SOURCES)
