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

SUBDIRS = reference

EXTRA_DIST = gdoc shishi.txt shishi.html shishi.ps shishi.pdf

info_TEXINFOS = shishi.texi
ps_TEXINFOS = shishi.texi
pdf_TEXINFOS = shishi.texi
shishi_TEXINFOS = gpl.texi fdl.texi $(gdoc_TEXINFOS) \
	shishi-api-error-labels.texi

shishi.txt: shishi.texi $(shishi_TEXINFOS)
	$(MAKEINFO) --no-header $< > $@

shishi.html: shishi.texi $(shishi_TEXINFOS)
	$(MAKEINFO) --html --no-split --number-sections $<

dist_man_MANS = shishi.1 $(gdoc_MANS)
DISTCLEANFILES = $(dist_man_MANS)

shishi.1: $(top_srcdir)/src/shishi.c $(top_builddir)/src/shishi
	$(HELP2MAN) \
		--name="kerberos 5 implementation" \
		--help-option="--program-name shishi --help" \
		--output=$@ $(top_builddir)/src/shishi

GDOC_SRC = $(top_srcdir)/lib/*.c
GDOC_TEXI_PREFIX = texi/
GDOC_MAN_PREFIX = man/
GDOC_MAN_EXTRA_ARGS = -module $(PACKAGE) -sourceversion $(VERSION) \
	-bugsto $(PACKAGE_BUGREPORT) -includefuncprefix -seeinfo $(PACKAGE) \
	-copyright "2002, 2003 Simon Josefsson" -verbatimcopying
include $(srcdir)/Makefile.gdoci

shishi-api-error-labels.texi: $(top_srcdir)/lib/error.c
	$(PERL) $(srcdir)/gdoc-error $^ > $@
