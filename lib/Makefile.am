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

INCLUDES = -I$(top_srcdir)/gl @LIBTASN1_CFLAGS@ \
	@LIBGCRYPT_CFLAGS@ @CRYPTO_CFLAGS@ @LIBGNUTLS_CFLAGS@

DEFS = -DLOCALEDIR=\"$(localedir)\" \
	-DSYSTEMCFGFILE=\"$(sysconfdir)/shishi.conf\" \
	-DSKELCFGFILE=\"$(pkgdatadir)/shishi.skel\" \
	-DHOSTKEYSFILE=\"$(sysconfdir)/shishi.keys\" \
	-DDMALLOC_FUNC_CHECK \
	@DEFS@

BUILT_SOURCES = shishi-int.h kerberos5.c
DISTCLEANFILES = shishi-int.h
MAINTAINERCLEANFILES = kerberos5.c
nodist_include_HEADERS = shishi-int.h

EXTRA_DIST = kerberos5.asn1

include_HEADERS = shishi.h
lib_LTLIBRARIES = libshishi.la
libshishi_la_SOURCES = shishi.h.in internal.h \
	init.c cfg.c realm.c principal.c error.c krberror.c \
	gztime.c diskio.c authorize.c \
	authenticator.c \
	kdc.c kdcreq.c kdcrep.c enckdcreppart.c as.c tgs.c \
	ap.c apreq.c aprep.c encapreppart.c \
	safe.c priv.c \
	ticket.c encticketpart.c tkt.c tkts.c \
	netio.c key.c keys.c hostkeys.c crypto.c crypto.h crypto-ctx.c \
	asn1.c kerberos5.c \
	version.c password.c \
	utils.c resolv.c
if NULL
libshishi_la_SOURCES += crypto-null.c
endif
if MD
libshishi_la_SOURCES += crypto-md.c
endif
if DES
libshishi_la_SOURCES += crypto-des.c
endif
if DES3
libshishi_la_SOURCES += crypto-3des.c
endif
if AES
libshishi_la_SOURCES += crypto-aes.c
endif
if ARCFOUR
libshishi_la_SOURCES += crypto-rc4.c
endif
if NETTLE
libshishi_la_SOURCES += nettle.c
endif
if LIBGCRYPT
libshishi_la_SOURCES += libgcrypt.c
endif
if STARTTLS
libshishi_la_SOURCES += starttls.c
endif
libshishi_la_LIBADD = @LIBGCRYPT_LIBS@ @CRYPTO_LIBS@ \
	@LTLIBINTL@ ../gl/libfoo.la @LIBTASN1_LIBS@ @LIBGNUTLS_LIBS@
libshishi_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

kerberos5.c: $(srcdir)/kerberos5.asn1
	-@ASN1PARSER@ -o $@ -n shishi_asn1_tab $^

indent:
	indent $(am__libshishi_la_SOURCES_DIST)
