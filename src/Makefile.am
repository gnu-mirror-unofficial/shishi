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

bin_PROGRAMS = shishi
sbin_PROGRAMS = shishid

shishi_SOURCES = data.h gettext.h shishi.c kdc.c authp.c crypto.c \
	list.c client.c server.c
shishi_LDADD = @LIBARGP@ @LTLIBINTL@ @LIBGCRYPT@ \
	../lib/libshishi.la ../asn1/lib/libtasn1.la

shishid_SOURCES = shishid.c
shishid_LDADD = @LIBARGP@ @LIBGCRYPT@ \
	../lib/libshishi.la ../asn1/lib/libtasn1.la

localedir = $(datadir)/locale

INCLUDES = -I../lib -I../argp -I../intl -DLOCALEDIR=\"$(localedir)\"

DEFS = -DSYSTEMCFGFILE=\"$(sysconfdir)/shishi.conf\" \
	-DSKELCFGFILE=\"$(pkgdatadir)/shishi.skel\" \
	@DEFS@

indent:
	indent $(shishi_SOURCES) $(shishid_SOURCES)
