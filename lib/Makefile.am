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

EXTRA_DIST = rfc1510.asn1 rfc1510bis.asn1 \
	crypto-null.c crypto-des.c crypto-3des.c crypto-aes.c \
	setenv.c unsetenv.c strdup.c memmove.c memset.c strcasecmp.c \
	strerror.c gethostname.c

lib_LTLIBRARIES = libshishi.la
libshishi_la_SOURCES = internal.h gettext.h \
	init.c cfg.c done.c realm.c principal.c error.c krberror.c \
	base64.c vasprintf.c \
	gztime.c diskio.c \
	authenticator.c \
	kdc.c kdcreq.c kdcrep.c enckdcreppart.c as.c tgs.c \
	ap.c apreq.c aprep.c encapreppart.c \
	ticketset.c ticket.c encticketpart.c \
	netio.c key.c crypto.c pkcs5.h pkcs5.c \
	rfc1510_asn1_tab.c asn1.c \
	version.c password.c \
	setenv.h
libshishi_la_LIBADD = @LIBGCRYPT_BUILD_LIBS@ @LIBSTRINGPREP_LIBS@ \
	../asn1/lib/ASN1.lo ../asn1/lib/decoding.lo ../asn1/lib/gstr.lo \
	../asn1/lib/errors.lo ../asn1/lib/parser_aux.lo \
	../asn1/lib/structure.lo ../asn1/lib/element.lo ../asn1/lib/coding.lo \
	@LTLIBOBJS@ @LTLIBINTL@
libshishi_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

INCLUDES = -I../asn1/lib -I../intl @LIBGCRYPT_BUILD_CFLAGS@ @STRINGPREP_CFLAGS@

include_HEADERS = shishi.h

DEFS = -DLOCALEDIR=\"$(localedir)\" \
	-DSYSTEMCFGFILE=\"$(sysconfdir)/shishi.conf\" \
	-DSKELCFGFILE=\"$(pkgdatadir)/shishi.skel\" \
	@DEFS@

rfc1510_asn1_tab.c: $(srcdir)/rfc1510.asn1
	../asn1/src/asn1Parser -o $@ -n shishi_asn1_tab $<

indent:
	indent $(SOURCES)
