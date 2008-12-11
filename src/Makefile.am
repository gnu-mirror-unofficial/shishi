## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008 Simon Josefsson.
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

SUBDIRS = gl

AM_CFLAGS = $(WARN_CFLAGS)
AM_CPPFLAGS = -I$(srcdir)/gl -I$(builddir)/gl \
	-I$(top_srcdir)/gl -I$(top_builddir)/gl \
	-I$(top_srcdir)/db -I../lib
localedir = $(datadir)/locale
DEFS = @DEFS@ -DLOCALEDIR=\"$(localedir)\" \
	-DSYSTEMCFGFILE=\"$(CONFDIR)/shishi.conf\" \
	-DHOSTKEYSFILE=\"$(KEYDIR)/shishi.keys\"

BUILT_SOURCES = shishi_cmd.c shishi_cmd.h shisa_cmd.c shisa_cmd.h	\
	shishid_cmd.c shishid_cmd.h keytab2shishi_cmd.c			\
	keytab2shishi_cmd.h ccache2shishi_cmd.c				\
	ccache2shishi_cmd.h
MAINTAINERCLEANFILES = $(BUILT_SOURCES)

bin_PROGRAMS = shishi shisa ccache2shishi
sbin_PROGRAMS = keytab2shishi
if ENABLE_SHISHID
sbin_PROGRAMS += shishid
endif

noinst_LTLIBRARIES =

shishi_SOURCES = shishi.c
shishi_LDADD = ../gl/libgnu.la gl/libgnu.la libcmd-shishi.la		\
	../lib/libshishi.la @LTLIBINTL@
noinst_LTLIBRARIES += libcmd-shishi.la
libcmd_shishi_la_CFLAGS =
libcmd_shishi_la_SOURCES = shishi.ggo shishi_cmd.h shishi_cmd.c
shishi_cmd.c shishi_cmd.h: shishi.ggo Makefile.am
	gengetopt --unamed-opts="CLIENT [SERVER]"			\
		--no-handle-help --no-handle-error --no-handle-version	\
		--input $< --file-name shishi_cmd

shisa_SOURCES = shisa.c
shisa_LDADD = ../gl/libgnu.la gl/libgnu.la libcmd-shishi.la		\
	../db/libshisa.la ../lib/libshishi.la @LTLIBINTL@
noinst_LTLIBRARIES += libcmd-shisa.la
libcmd_shisa_la_CFLAGS =
libcmd_shisa_la_SOURCES = shisa.ggo shisa_cmd.h shisa_cmd.c
shisa_cmd.c shisa_cmd.h: shisa.ggo Makefile.am
	gengetopt --unamed-opts="REALM [PRINCIPAL]"			\
		--no-handle-help --no-handle-error --no-handle-version	\
		--input $< --file-name shisa_cmd

shishid_SOURCES = shishid.c server.c kdc.h kdc.c
if STARTTLS
shishid_SOURCES += starttls.c resume.c
endif
shishid_LDADD = ../gl/libgnu.la gl/libgnu.la ../lib/libshishi.la \
	../db/libshisa.la @LTLIBGNUTLS@ @LTLIBINTL@ libcmd-shishid.la
noinst_LTLIBRARIES += libcmd-shishid.la
libcmd_shishid_la_CFLAGS =
libcmd_shishid_la_SOURCES = shishid.ggo shishid_cmd.h shishid_cmd.c
shishid_cmd.c shishid_cmd.h: shishid.ggo Makefile.am
	gengetopt							\
		--no-handle-help --no-handle-error --no-handle-version	\
		--input $< --file-name shishid_cmd

keytab2shishi_SOURCES = keytab2shishi.c
keytab2shishi_LDADD = ../gl/libgnu.la gl/libgnu.la libcmd-keytab2shishi.la \
	../lib/libshishi.la @LTLIBINTL@
noinst_LTLIBRARIES += libcmd-keytab2shishi.la
libcmd_keytab2shishi_la_CFLAGS =
libcmd_keytab2shishi_la_SOURCES =  keytab2shishi.ggo			\
	keytab2shishi_cmd.h keytab2shishi_cmd.c
keytab2shishi_cmd.c keytab2shishi_cmd.h: keytab2shishi.ggo Makefile.am
	gengetopt --unamed-opts="INFILE [OUTFILE]"			\
		--no-handle-help --no-handle-error			\
		--input $< --file-name keytab2shishi_cmd

ccache2shishi_SOURCES = ccache2shishi.c
ccache2shishi_LDADD = ../gl/libgnu.la gl/libgnu.la libcmd-ccache2shishi.la \
	../lib/libshishi.la @LTLIBINTL@
noinst_LTLIBRARIES += libcmd-ccache2shishi.la
libcmd_ccache2shishi_la_CFLAGS =
libcmd_ccache2shishi_la_SOURCES = ccache2shishi.ggo			\
	ccache2shishi_cmd.h ccache2shishi_cmd.c
ccache2shishi_cmd.c ccache2shishi_cmd.h: ccache2shishi.ggo Makefile.am
	gengetopt --unamed-opts="INFILE [OUTFILE]"			\
		--no-handle-help --no-handle-error			\
		--input $< --file-name ccache2shishi_cmd
