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

HIGNORE = asn1.h cfg.h crypto.h diskio.h internal.h resolver.h	\
	shishi-int.h starttls.h utils.h

HTML_OBJECTS = index.html c4.html shishi-shishi.html

EXTRA_DIST = $(PACKAGE)-docs.tmpl $(HTML_OBJECTS) $(IMAGES)
IMAGES = home.png left.png right.png up.png

scan.stamp: $(top_srcdir)/lib/*.c $(top_srcdir)/lib/*.h
	gtkdoc-scan --module=$(PACKAGE) --source-dir=$(top_srcdir)/lib \
		--ignore-headers="$(HIGNORE)" && touch scan.stamp

tmpl.stamp: scan.stamp
	gtkdoc-mktmpl --module=$(PACKAGE) --output-dir=.

sgml.stamp: tmpl.stamp
	gtkdoc-mkdb --module=$(PACKAGE) --source-dir=$(top_srcdir)/lib \
		--tmpl-dir=. --output-dir=. \
		--main-sgml-file=$(srcdir)/$(PACKAGE)-docs.tmpl

index.html: sgml.stamp
	cp $(srcdir)/$(PACKAGE)-docs.tmpl $(PACKAGE)-docs.sgml
	gtkdoc-mkhtml $(PACKAGE) $(PACKAGE)-docs.sgml
	rm -f $(PACKAGE)-docs.sgml ../html.stamp
	gtkdoc-fixxref --module-dir=. --html-dir=$(HTML_DIR)

all: index.html

clean-local:
	rm -f *.bak scan.stamp tmpl.stamp sgml.stamp *.txt *.sgml \
		$(PACKAGE)-doc.bottom $(PACKAGE)-doc.top \
		$(HTML_OBJECTS) $(IMAGES) 
