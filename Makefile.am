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

DISTCHECK_CONFIGURE_FLAGS = --disable-gtk-doc

MOST_SUBDIRS = m4 po gl lib src tests examples doc

DIST_SUBDIRS = crypto asn1 $(MOST_SUBDIRS) extra

SUBDIRS = @CRYPTO@ @ASN1@ $(MOST_SUBDIRS)

ACLOCAL_AMFLAGS = -I m4 -I gl/m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = shishi.pc

sysconf_DATA = shishi.conf
pkgdata_DATA = shishi.skel

EXTRA_DIST = ANNOUNCE config.rpath mkinstalldirs \
	shishi.conf.in shishi.skel.in shishi.pc.in

# Maintainer targets

indent:
	(cd lib && make indent)
	(cd src && make indent)
	(cd tests && make indent)

.PHONY: extra
extra:
	(cd extra && make)

ChangeLog:
	test ! -f .cvsusers || \
	(cvs2cl --fsf --FSF --usermap .cvsusers \
	-I "ChangeLog|.cvs|autogen.sh|doc/specification|libstringprep" && \
	cat .cvscopying >> ChangeLog)

tag = $(PACKAGE)-`echo $(VERSION) | sed 's/\./-/g'`
htmldir = ../www-$(PACKAGE)

release:
	cvs upd -p -r HEAD NEWS > /dev/null
	if cvs upd -p -r $(tag) NEWS > /dev/null; then false else true; fi
	rm -f ChangeLog && cvs upd ChangeLog
	cvs commit
	rm -f ChangeLog
	$(MAKE) ChangeLog distcheck
	cvs commit -m "" ChangeLog
	rm -f $(distdir).tar.gz.asc
	gpg -a --sign --detach $(distdir).tar.gz
	gpg --verify $(distdir).tar.gz.asc
	cvs rtag $(tag) $(PACKAGE)
	test -d $(htmldir) && cp -v doc/$(PACKAGE).{ps,pdf,html} $(htmldir)/
	test -d $(htmldir)/reference && \
		cp -v doc/reference/html/*.html $(htmldir)/reference/
	test -d $(htmldir) && cd $(htmldir) && cvs commit -m "Update." \
		$(PACKAGE).{ps,pdf,html} reference/*.html
