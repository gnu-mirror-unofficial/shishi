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

DISTCHECK_CONFIGURE_FLAGS = --without-system-asn1 --without-libgcrypt

SUBDIRS = po gl

if ASN1
SUBDIRS += asn1
endif
if NETTLE
SUBDIRS += crypto
endif

SUBDIRS += lib db src tests doc

DIST_SUBDIRS = po gl asn1 crypto lib db src tests doc examples extra

ACLOCAL_AMFLAGS = -I m4 -I gl/m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = shishi.pc

confdir = $(CONFDIR)
conf_DATA = shishi.conf shisa.conf

skeldir = $(SKELDIR)
skel_DATA = shishi.skel

install-exec-hook:
	@echo Initializing database and creating host key...
	if test ! -d $(DESTDIR)$(DBDIR); then \
	  if mkdir -m 0700 -p $(DESTDIR)$(DBDIR); then \
	    if test ! -f $(DESTDIR)$(KEYDIR)/shishi.keys; then \
	      if $(DESTDIR)$(bindir)/shisa$(EXEEXT) -a > \
			$(DESTDIR)$(KEYDIR)/shishi.keys; then \
	        echo Successfully created database and host key.; \
	      else \
	        echo Unable to create database, see $(DESTDIR)$(KEYDIR)/shishi.keys.; \
	      fi; \
	    else \
	      echo Key file $(DESTDIR)$(KEYDIR)/shishi.keys already exist.; \
	    fi; \
	  else \
	    echo Could not create directory root$(DESTDIR)$(DBDIR).; \
	  fi; \
	else \
	  echo Database root $(DESTDIR)$(DBDIR) already exist.; \
	fi

# Maintainer targets

indent:
	(cd lib && make indent)
	(cd db && make indent)
	(cd src && make indent)
	(cd tests && make indent)

.PHONY: extra
extra:
	(cd extra && make)

.PHONY: examples
examples:
	(cd examples && make)

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
