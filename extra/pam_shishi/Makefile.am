## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2005 Simon Josefsson.
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

lib_LTLIBRARIES = pam_shishi.la

pam_shishi_la_SOURCES = pam_shishi.c
pam_shishi_la_LIBADD = ../../lib/libshishi.la
# XXX add -Wl,-x too?  PAM documentation suggests it.
pam_shishi_la_LDFLAGS = -module

INCLUDES = -I$(top_srcdir)/gl -I$(top_builddir)/gl -I../../lib

# -DDEBUG_PAM
DEFS = @DEFS@

indent:
	indent $(SOURCES)
