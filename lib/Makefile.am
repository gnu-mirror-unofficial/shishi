## Process this file with automake to produce Makefile.in
# Copyright (C) 2002 Simon Josefsson.
#
# This file is part of Shishi.
#
# Shishi is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# Shishi is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with Shishi; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

EXTRA_DIST = rfc1510.asn1 rfc1510bis.asn1

lib_LTLIBRARIES = libshishi.la
libshishi_la_SOURCES = internal.h gettext.h \
	init.c cfg.c done.c realm.c principal.c error.c base64.c \
	gztime.c diskio.c \
	authenticator.c \
	kdc.c kdcreq.c kdcrep.c enckdcreppart.c \
	ap.c apreq.c aprep.c encapreppart.c \
	ticketset.c ticket.c encticketpart.c \
	netio.c crypto.c \
	rfc1510_asn1_tab.c asn1.c \
	version.c password.c
libshishi_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

INCLUDES = -I../asn1/lib @LIBGCRYPT_CFLAGS@ @GNET_CFLAGS@

include_HEADERS = shishi.h

DEFS = -DLOCALEDIR=\"$(localedir)\" \
	-DSYSTEMCFGFILE=\"$(sysconfdir)/shishi.conf\" \
	-DSKELCFGFILE=\"$(pkgdatadir)/shishi.skel\" \
	@DEFS@

rfc1510_asn1_tab.c: $(srcdir)/rfc1510.asn1
	../asn1/src/asn1Parser -o $@ -n shishi_asn1_tab $<

indent:
	indent $(libshishi_la_SOURCES)
