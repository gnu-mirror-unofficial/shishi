# Copyright (C) 2006-2021 Simon Josefsson.
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

WFLAGS ?= --enable-gcc-warnings
ADDFLAGS ?=
CFGFLAGS ?= --enable-gtk-doc --enable-gtk-doc-pdf \
	--with-libgcrypt $(ADDFLAGS) $(WFLAGS)

INDENT_SOURCES = `find . -name \*.[ch] | grep -v -e ^./asn1/ -e ^./build-aux/ -e ^./db/gl/ -e ^./extra/rsh-redone/ -e ^./gl/ -e ^./lib/kerberos5.c -e ^./src/gl/`

ifeq ($(.DEFAULT_GOAL),abort-due-to-no-makefile)
.DEFAULT_GOAL := bootstrap
endif

local-checks-to-skip = sc_copyright_check sc_error_message_uppercase	\
	sc_immutable_NEWS sc_makefile_at_at_check sc_po_check		\
	sc_prohibit_atoi_atof sc_prohibit_have_config_h			\
	sc_prohibit_strcmp sc_require_config_h				\
	sc_require_config_h_first sc_GPL_version
VC_LIST_ALWAYS_EXCLUDE_REGEX = ^GNUmakefile|maint.mk|gtk-doc.make|asn1/.*\.[ch]|build-aux/|doc/keytab.txt|doc/fdl-1.3.texi|doc/gdoc|doc/parse-datetime.texi|doc/specifications/.*|extra/.*\.[1ch]|m4/pkg.m4|po/.*.po.in|((db/|src/)?gl)/.*$$

update-copyright-env = UPDATE_COPYRIGHT_HOLDER="Simon Josefsson" UPDATE_COPYRIGHT_USE_INTERVALS=2

# Explicit syntax-check exceptions.
exclude_file_name_regexp--sc_bindtextdomain = ^examples/|extra/|lib/ccache.c|tests/utils.c
exclude_file_name_regexp--sc_prohibit_doubled_word = ^doc/shishi.texi|lib/
exclude_file_name_regexp--sc_prohibit_empty_lines_at_EOF = ^doc/components.dia|doc/components.png|tests/ccache1.bin|tests/keytab1.bin
exclude_file_name_regexp--sc_cast_of_argument_to_free = ^lib/keys.c|lib/tkts.c|extra/pam_shishi/pam_shishi.c
exclude_file_name_regexp--sc_program_name = ^examples/|extra/|lib/|tests/
exclude_file_name_regexp--sc_prohibit_cvs_keyword = ^extra/rsh-redone/
exclude_file_name_regexp--sc_prohibit_magic_number_exit = ^extra/rsh-redone/
exclude_file_name_regexp--sc_space_tab = ^doc/components.dia|extra/rsh-redone/
exclude_file_name_regexp--sc_trailing_blank = ^doc/components.png|doc/shishi.texi|extra/fetchmail.diff|extra/rsh-redone/
exclude_file_name_regexp--sc_two_space_separator_in_usage = ^doc/shishi.texi
exclude_file_name_regexp--sc_unmarked_diagnostics = ^extra/rsh-redone/|src/shisa.c|src/shishi.c|src/shishid.c
exclude_file_name_regexp--sc_useless_cpp_parens = ^extra/rsh-redone/
exclude_file_name_regexp--sc_prohibit_strncpy =^lib/error.c|src/shishid.c

autoreconf:
	for f in po/*.po.in; do \
		cp $$f `echo $$f | sed 's/.in//'`; \
	done
	mv build-aux/config.rpath build-aux/config.rpath-
	test -f ./configure || autoreconf --install
	mv build-aux/config.rpath- build-aux/config.rpath

update-po: refresh-po
	for f in `ls po/*.po | grep -v quot.po`; do \
		cp $$f $$f.in; \
	done
	git add po/*.po.in
	git commit -m "Sync with TP." po/LINGUAS po/*.po.in

bootstrap: autoreconf
	./configure $(CFGFLAGS)

# Code Coverage

web-coverage:
	rm -fv `find $(htmldir)/coverage -type f | grep -v CVS`
	cp -rv doc/coverage/* $(htmldir)/coverage/

upload-web-coverage:
	cd $(htmldir) && \
		cvs commit -m "Update." coverage

# Mingw32

W32ROOT ?= $(HOME)/gnutls4win/inst

mingw32: autoreconf
	./configure $(CFGFLAGS) --host=i586-mingw32msvc --build=`./config.guess` --prefix=$(W32ROOT)

ChangeLog:
	git2cl > ChangeLog
	cat .clcopying >> ChangeLog

htmldir = ../www-$(PACKAGE)
tag = $(PACKAGE)-`echo $(VERSION) | sed 's/\./-/g'`

release: prepare upload web upload-web

prepare:
	! git tag -l $(tag) | grep $(PACKAGE) > /dev/null
	rm -f ChangeLog
	$(MAKE) ChangeLog distcheck
	git commit -m Generated. ChangeLog
	git tag -u b565716f! -m $(VERSION) $(tag)

upload:
	git push
	git push --tags
	build-aux/gnupload --to ftp.gnu.org:shishi $(distdir).tar.gz
	cp $(distdir).tar.gz $(distdir).tar.gz.sig ../releases/$(PACKAGE)/

web:
	cd doc && ../build-aux/gendocs.sh --html "--css-include=texinfo.css" \
		--email $(PACKAGE_BUGREPORT) \
		-o ../$(htmldir)/tmpmanual/ $(PACKAGE) "$(PACKAGE_NAME)"
	rsync -r $(htmldir)/tmpmanual/ $(htmldir)/manual/
	rm -rf $(htmldir)/tmpmanual/
	cp -v doc/reference/$(PACKAGE).pdf doc/reference/html/*.html doc/reference/html/*.png doc/reference/html/*.devhelp2 doc/reference/html/*.css $(htmldir)/reference/
	cp -v doc/cyclo/cyclo-$(PACKAGE).html $(htmldir)/cyclo/

upload-web:
	cd $(htmldir) && \
		cvs commit -m "Update." manual/ reference/ cyclo/

review-diff:
	git diff `git describe --abbrev=0`.. \
	| grep -v -e ^index -e '^diff --git' \
	| filterdiff -p 1 -x 'build-aux/*' -x 'gl/*' -x 'db/gl/*' -x 'src/gl/*' -x 'po/*' -x 'maint.mk' -x '.gitignore' -x '.x-sc*' -x ChangeLog -x GNUmakefile \
	| less
