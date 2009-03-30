## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Simon Josefsson.
#
# This file is part of Shishi.
#
# Shishi is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# Shishi is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Shishi; if not, see http://www.gnu.org/licenses or write
# to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
# Floor, Boston, MA 02110-1301, USA.

AM_CFLAGS = $(WARN_CFLAGS) $(CFLAG_VISIBILITY)
AM_CPPFLAGS = $(LIBTASN1_CFLAGS) -I$(top_srcdir)/gl -I$(top_builddir)/gl

DEFS = @DEFS@ -DLOCALEDIR=\"$(localedir)\" \
	-DSYSTEMCFGFILE=\"$(CONFDIR)/shishi.conf\" \
	-DSKELCFGFILE=\"$(SKELDIR)/shishi.skel\" \
	-DHOSTKEYSFILE=\"$(KEYDIR)/shishi.keys\"

BUILT_SOURCES = shishi-int.h kerberos5.c
DISTCLEANFILES = shishi-int.h
MAINTAINERCLEANFILES = kerberos5.c
nodist_include_HEADERS = shishi-int.h

shishi-int.h:
	if test -n "$(STDINT_H)"; then \
		cp ../gl/stdint.h shishi-int.h; \
	else \
		echo '#include <stdint.h>' > shishi-int.h; \
	fi

include_HEADERS = shishi.h
lib_LTLIBRARIES = libshishi.la
libshishi_la_SOURCES = libshishi.map \
	shishi.h internal.h \
	init.c cfg.c cfg.h realm.c principal.c error.c krberror.c \
	gztime.c diskio.c diskio.h authorize.c pki.c \
	authenticator.c \
	kdc.c kdcreq.c kdcrep.c enckdcreppart.c as.c tgs.c \
	ap.c apreq.c aprep.c encapreppart.c \
	safe.c priv.c \
	ticket.c encticketpart.c tkt.c tkts.c tktccache.c \
	ccache.c ccache.h \
	netio.c \
	key.c keys.c keytab.c hostkeys.c \
	crypto.c crypto.h crypto-ctx.c \
	asn1.c asn1.h kerberos5.c \
	version.c password.c \
	utils.c utils.h resolv.c \
	kerberos5.asn1 \
	low-crypto.c low-crypto.h

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
if STARTTLS
libshishi_la_SOURCES += starttls.c starttls.h
endif
libshishi_la_LIBADD = ../gl/libgnu.la $(LIB_CLOCK_GETTIME)	\
	$(LTLIBTASN1) $(LTLIBGNUTLS) $(LTLIBGCRYPT) $(LTLIBIDN)	\
	$(LTLIBINTL)
libshishi_la_LDFLAGS = -no-undefined \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

if HAVE_LD_VERSION_SCRIPT
libshishi_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libshishi.map
else
libshishi_la_LDFLAGS += -export-symbols-regex '^shishi.*'
endif

if HAVE_LD_OUTPUT_DEF
libshishi_la_LDFLAGS += -Wl,--output-def,libshishi-$(SOVERSION).def
defexecdir = $(bindir)
defexec_DATA = libshishi-$(SOVERSION).def
DISTCLEANFILES += $(defexec_DATA)
endif

kerberos5.c: $(srcdir)/kerberos5.asn1
	-@ASN1PARSER@ -o $@ -n shishi_asn1_tab $^
