## Process this file with automake to create Makefile.in
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

shishi_texi_auto_deps = shishi-api-global.texi \
	shishi-api-ticket.texi shishi-api-ticketset.texi \
	shishi-api-as.texi shishi-api-tgs.texi \
	shishi-api-kdc.texi shishi-api-authenticator.texi shishi-api-ap.texi \
	shishi-api-key.texi shishi-api-crypto.texi \
	shishi-api-error.texi shishi-api-error-labels.texi \
	shishi-api-version.texi

generated = shishi.txt shishi.html shishi.ps shishi.pdf \
	shishi.info shishi.info-1 shishi.info-2 \
	$(shishi_texi_auto_deps)

man_MANS = shishi.1

MAINTAINERCLEANFILES = $(generated)

DISTCLEANFILES = $(man_MANS)

EXTRA_DIST = gdoc $(man_MANS) $(generated)

info_TEXINFOS = shishi.texi
shishi_TEXINFOS = lgpl.texi gpl.texi fdl.texi $(shishi_texi_auto_deps)

shishi-api-global.texi: $(top_srcdir)/lib/init.c $(top_srcdir)/lib/done.c
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

shishi-api-ticket.texi: $(top_srcdir)/lib/ticket.c
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

shishi-api-ticketset.texi: $(top_srcdir)/lib/ticketset.c
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

shishi-api-as.texi: $(top_srcdir)/lib/as.c
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

shishi-api-tgs.texi: $(top_srcdir)/lib/tgs.c
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

shishi-api-kdc.texi: $(top_srcdir)/lib/kdc.c $(top_srcdir)/lib/kdcreq.c $(top_srcdir)/lib/kdcrep.c $(top_srcdir)/lib/enckdcreppart.c
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

shishi-api-authenticator.texi: $(top_srcdir)/lib/authenticator.c
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

shishi-api-ap.texi: $(top_srcdir)/lib/ap.c $(top_srcdir)/lib/apreq.c $(top_srcdir)/lib/aprep.c
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

shishi-api-key.texi: $(top_srcdir)/lib/key.c
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

shishi-api-crypto.texi: $(top_srcdir)/lib/crypto.c
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

shishi-api-error.texi: $(top_srcdir)/lib/error.c
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

shishi-api-error-labels.texi: $(top_srcdir)/lib/error.c
	$(PERL) $(srcdir)/gdoc-error -texinfo $^ > $@

shishi-api-version.texi: $(top_srcdir)/lib/version.c
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

shishi.1: $(top_srcdir)/src/shishi.c $(top_builddir)/src/shishi
	$(HELP2MAN) \
		--name="kerberos 5 implementation" \
		--output=$@ $(top_builddir)/src/shishi

# Texinfo:

shishi.txt: shishi.texi
	$(MAKEINFO) --no-header $< > $@

shishi.html: shishi.texi
	$(MAKEINFO) --html --no-split --number-sections $<

shishi.ps: shishi.texi

shishi.pdf: shishi.texi
	$(TEXI2PDF) $<
