## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004 Simon Josefsson.
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

if ENABLE_GTK_DOC
SUBDIRS = reference
endif

EXTRA_DIST = gdoc shishi.html shishi.pdf shishi.ps texinfo.css

info_TEXINFOS = shishi.texi
shishi_TEXINFOS = gpl.texi fdl.texi $(gdoc_TEXINFOS) \
	shishi-api-error-labels.texi

AM_MAKEINFOHTMLFLAGS = --no-split --number-sections --css-include=texinfo.css

dist_man_MANS = shishi.1 shisa.1 shishid.1 $(gdoc_MANS)
MAINTAINERCLEANFILES = $(dist_man_MANS)

shishi.1: $(top_srcdir)/src/shishi.c $(top_srcdir)/src/shishi.ggo \
		$(top_srcdir)/configure.ac
	$(HELP2MAN) \
		--name="Shishi client tool" \
		--output=$@ $(top_builddir)/src/shishi

shisa.1: $(top_srcdir)/src/shisa.c $(top_srcdir)/src/shisa.ggo \
		$(top_srcdir)/configure.ac
	$(HELP2MAN) \
		--name="Shishi database interface" \
		--info-page=shishi \
		--output=$@ $(top_builddir)/src/shisa

shishid.1: $(top_srcdir)/src/shishid.c $(top_srcdir)/src/shishid.ggo \
		$(top_srcdir)/configure.ac
	$(HELP2MAN) \
		--name="Shishi KDC server" \
		--output=$@ $(top_builddir)/src/shishid

GDOC_SRC = $(top_srcdir)/lib/*.c $(top_srcdir)/db/*.c
GDOC_TEXI_PREFIX = texi/
GDOC_MAN_PREFIX = man/
GDOC_MAN_EXTRA_ARGS = -module $(PACKAGE) -sourceversion $(VERSION) \
	-bugsto $(PACKAGE_BUGREPORT) -includefuncprefix -seeinfo $(PACKAGE) \
	-copyright "2002, 2003, 2004 Simon Josefsson" -verbatimcopying
include $(srcdir)/Makefile.gdoci

shishi-api-error-labels.texi: $(top_srcdir)/lib/error.c
	$(PERL) $(srcdir)/gdoc-error $^ > $@
