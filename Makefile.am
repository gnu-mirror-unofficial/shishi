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

MOST_SUBDIRS = intl m4 po asn1 argp lib src test doc

DIST_SUBDIRS = crypto $(MOST_SUBDIRS)

SUBDIRS = @CRYPTO@ $(MOST_SUBDIRS)

ACLOCAL_AMFLAGS = -I m4 -I crypto/src -I asn1/src

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = shishi.pc

sysconf_DATA = shishi.conf
pkgdata_DATA = shishi.skel

EXTRA_DIST = config.rpath mkinstalldirs  config.rpath shishi.conf.in shishi.skel.in shishi.pc.in

ChangeLog:
	cvs2cl --fsf --usermap .cvsusers --separate-header -I \
	"ChangeLog|.cvsignore|.cvsusers|autogen.sh|doc/specification/.*"
