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

MOST_SUBDIRS = intl m4 po asn1 lib src tests doc extra

DIST_SUBDIRS = crypto argp libstringprep $(MOST_SUBDIRS)

SUBDIRS = @CRYPTO@ @ARGP@ @STRINGPREP@ $(MOST_SUBDIRS)

ACLOCAL_AMFLAGS = -I m4 -I crypto/src -I asn1/src

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = shishi.pc

sysconf_DATA = shishi.conf
pkgdata_DATA = shishi.skel

EXTRA_DIST = config.rpath mkinstalldirs \
	shishi.conf.in shishi.skel.in shishi.pc.in \
	gdbm/COPYING gdbm/ChangeLog gdbm/INSTALL gdbm/Makefile.in gdbm/NEWS \
	gdbm/README gdbm/aclocal.m4 \
	gdbm/bucket.c gdbm/close.c gdbm/config.guess \
	gdbm/config.sub gdbm/configure.in \
	gdbm/conv2gdbm.c gdbm/dbm.h gdbm/dbmclose.c gdbm/dbmdelete.c \
	gdbm/dbmdirfno.c gdbm/dbmfetch.c gdbm/dbminit.c gdbm/dbmopen.c \
	gdbm/dbmpagfno.c gdbm/dbmrdonly.c gdbm/dbmseq.c gdbm/dbmstore.c \
	gdbm/delete.c gdbm/extern.h gdbm/falloc.c gdbm/fetch.c \
	gdbm/findkey.c gdbm/gdbm.3 gdbm/gdbm.info gdbm/gdbm.proto \
	gdbm/gdbm.proto2 gdbm/gdbm.texinfo gdbm/gdbmclose.c gdbm/gdbmconst.h \
	gdbm/gdbmdefs.h gdbm/gdbmdelete.c gdbm/gdbmerrno.c \
	gdbm/gdbmerrno.h gdbm/gdbmexists.c gdbm/gdbmfdesc.c gdbm/gdbmfetch.c \
	gdbm/gdbmopen.c gdbm/gdbmreorg.c gdbm/gdbmseq.c gdbm/gdbmsetopt.c \
	gdbm/gdbmstore.c gdbm/gdbmsync.c gdbm/getopt.c gdbm/getopt.h \
	gdbm/global.c gdbm/hash.c gdbm/install-sh \
	gdbm/mkinstalldirs gdbm/ndbm.h gdbm/proto.h gdbm/seq.c gdbm/store.c \
	gdbm/systems.h gdbm/testdbm.c gdbm/testgdbm.c gdbm/testndbm.c \
	gdbm/update.c gdbm/version.c

ChangeLog:
	cvs2cl --fsf --usermap .cvsusers --separate-header -I \
	"ChangeLog|.cvsignore|.cvsusers|autogen.sh|doc/specification"

indent:
	(cd lib && make indent)
	(cd src && make indent)
	(cd tests && make indent)

sign: $(distdir).tar.gz
	rm -f $(distdir).tar.gz.asc
	gpg -a --sign --detach $(distdir).tar.gz
	gpg --verify $(distdir).tar.gz.asc
