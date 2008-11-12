## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2005, 2006, 2007, 2008 Simon Josefsson.
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

AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_builddir)/gl -I../../lib

libdir = $(PAMDIR)

lib_LTLIBRARIES = pam_shishi.la

pam_shishi_la_SOURCES = pam_shishi.c
pam_shishi_la_LIBADD = ../../lib/libshishi.la
# XXX add -Wl,-x too?  PAM documentation suggests it.
pam_shishi_la_LDFLAGS = -module -avoid-version

# -DDEBUG_PAM
DEFS = @DEFS@
