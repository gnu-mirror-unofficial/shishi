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

# -I../lib is to get shishi-int.h and uint32_t.
AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_builddir)/gl -I../lib

DEFS = -DLOCALEDIR=\"$(localedir)\" \
	-DSYSTEMCFGFILE=\"$(CONFDIR)/shisa.conf\" \
	-DDEFAULTDBPATH=\"$(DBDIR)\" \
	@DEFS@

include_HEADERS = shisa.h
lib_LTLIBRARIES = libshisa.la
libshisa_la_SOURCES = shisa.h info.h \
	setup.c config.c db.c err.c core.c \
	file.c file.h fileutil.h fileutil.c
libshisa_la_LIBADD = ../gl/libgnu.la
# XXX use different libtool version for this library?
libshisa_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)
