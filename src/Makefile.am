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

bin_PROGRAMS = shishi
sbin_PROGRAMS = shishid

shishi_SOURCES = shishi.c data.h gettext.h \
	authp.c crypto.c client.c server.c
shishi_LDADD = @LTLIBINTL@ ../gl/libfoo.a ../lib/libshishi.la

shishid_SOURCES = shishid.c
shishid_LDADD = ../gl/libfoo.a ../lib/libshishi.la

localedir = $(datadir)/locale

INCLUDES = -I../asn1/lib -I../gl -I../lib -I../intl \
	-DLOCALEDIR=\"$(localedir)\"

DEFS = -DSYSTEMCFGFILE=\"$(sysconfdir)/shishi.conf\" \
	-DSKELCFGFILE=\"$(pkgdatadir)/shishi.skel\" \
	@DEFS@

indent:
	indent $(SOURCES)
