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

EXTRA_DIST = gdoc shishi.txt shishi.html shishi.ps shishi.pdf \
	shishi-db.xml shishi-db.txt shishi-db.ps shishi-db.pdf \
	$(shishi_html_auto_deps)

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

# DocBook

shishi_html_auto_deps = html/a7608.html html/a7612.html			\
	html/a7850.html html/a7966.html html/c16.html html/c501.html	\
	html/c574.html html/c603.html html/c710.html html/c7602.html	\
	html/c9.html html/i8060.html html/i8199.html html/index.html	\
	html/x102.html html/x114.html html/x1366.html html/x24.html	\
	html/x2556.html html/x308.html html/x3224.html html/x3670.html	\
	html/x3889.html html/x4152.html html/x4270.html html/x434.html	\
	html/x453.html html/x471.html html/x5246.html html/x557.html	\
	html/x5750.html html/x697.html html/x703.html html/x7263.html	\
	html/x7441.html html/x7578.html html/x7591.html			\
	html/x7656.html html/x7701.html html/x8035.html html/x804.html	\
	html/x996.html

shishi-db.xml: shishi.texi $(shishi_TEXINFOS)
	$(MAKEINFO) --docbook --output $@ shishi.texi

$(shishi_html_auto_deps): shishi-db.xml
	$(DOCBOOK2HTML) -o html $^

shishi-db.txt: shishi-db.xml
	$(DOCBOOK2TXT) $^

shishi-db.pdf: shishi-db.xml
	$(DOCBOOK2PDF) $^

shishi-db.ps: shishi-db.xml
	$(DOCBOOK2PS) $^
