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

CRYPTO_INCLUDES = crypto-null.c crypto-des.c crypto-3des.c crypto-aes.c

EXTRA_DIST = kerberos5.asn1 $(CRYPTO_INCLUDES)

lib_LTLIBRARIES = libshishi.la
libshishi_la_SOURCES = internal.h gettext.h \
	init.c cfg.c done.c realm.c principal.c error.c krberror.c \
	base64.c \
	gztime.c diskio.c \
	authenticator.c \
	kdc.c kdcreq.c kdcrep.c enckdcreppart.c as.c tgs.c \
	ap.c apreq.c aprep.c encapreppart.c safe.c \
	ticket.c encticketpart.c tkt.c tkts.c \
	netio.c hostkeys.c key.c crypto.c pkcs5.h pkcs5.c \
	asn1.c kerberos5.c \
	version.c password.c \
	resolv.c
libshishi_la_LIBADD = @LIBTASN1_LIBS@ @LIBGCRYPT_LIBS@ @LIBIDN_LIBS@ \
	@LTLIBINTL@ -L../gl -lfoo
libshishi_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

INCLUDES = -I$(top_srcdir)/gl -I../intl \
	@LIBTASN1_CFLAGS@ @LIBGCRYPT_CFLAGS@ @LIBIDN_CFLAGS@

include_HEADERS = shishi.h

DEFS = -DLOCALEDIR=\"$(localedir)\" \
	-DSYSTEMCFGFILE=\"$(sysconfdir)/shishi.conf\" \
	-DSKELCFGFILE=\"$(pkgdatadir)/shishi.skel\" \
	-DHOSTKEYSFILE=\"$(sysconfdir)/shishi.keys\" \
	-DDMALLOC_FUNC_CHECK \
	@DEFS@

kerberos5.c: $(srcdir)/kerberos5.asn1
	-@ASN1PARSER@ -o $@ -n shishi_asn1_tab $^

indent:
	indent $(SOURCES) $(CRYPTO_INCLUDES) shishi.h.in
