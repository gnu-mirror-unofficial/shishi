## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004, 2005, 2006 Simon Josefsson.
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
# along with Shishi; see the file COPYING.  If not, write to the Free
# Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.

DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc \
	--without-system-asn1 --without-libgcrypt

SUBDIRS = po gl

if ASN1
SUBDIRS += asn1
endif

SUBDIRS += lib db src tests doc

DIST_SUBDIRS = po gl asn1 lib db src tests doc examples extra

ACLOCAL_AMFLAGS = -I m4 -I gl/m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = shishi.pc

confdir = $(CONFDIR)
conf_DATA = shishi.conf shisa.conf

skeldir = $(SKELDIR)
skel_DATA = shishi.skel

distuninstallcheck_listfiles = find . -type f -print | grep -v -e shishi.keys -e 0.key

install-data-hook:
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

.PHONY: extra
extra:
	(cd extra && make)

.PHONY: examples
examples:
	(cd examples && make)

ChangeLog:
	cvs2cl --fsf --FSF --usermap .cvsusers -I ChangeLog -I .cvs \
		-I autogen.sh -I doc/specification
	cat .cvscopying >> ChangeLog

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
	cvs rtag $(tag) $(PACKAGE)
	cd doc && ./gendocs.sh --html "--css-include=texinfo.css" \
		-o ../$(htmldir)/manual/ $(PACKAGE) "Shishi"
	gnupload --to alpha.gnu.org:libidn --user AABB1F7B! $(distdir).tar.gz
	cp -v $(distdir).tar.gz{,.sig} $(htmldir)/releases/
	cp -v doc/reference/html/*.{html,png,devhelp,css} $(htmldir)/reference/
	cd $(htmldir) && cvs add -kb releases/$(distdir).tar.gz{,.sig} && \
		cvs commit -m "Update." manual/ reference/ releases/

