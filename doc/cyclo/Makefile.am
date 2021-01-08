## Process this file with automake to produce Makefile.in
# Copyright (C) 2002-2021 Simon Josefsson
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

EXTRA_DIST = cyclo-$(PACKAGE).html

vcurl = "http://git.savannah.gnu.org/gitweb/?p=$(PACKAGE).git;a=blob;f=lib/%FILENAME%;hb=HEAD"

cyclo-$(PACKAGE).html:
	(cd ${top_srcdir}/lib && \
		$(PMCCABE) *.[ch] \
		| sort -nr \
		| LANG=C $(AWK) -f ${abs_top_srcdir}/build-aux/pmccabe2html \
			-v lang=html -v name="$(PACKAGE_STRING)" \
			-v vcurl=$(vcurl) \
			-v url="http://www.gnu.org/software/$(PACKAGE)/" \
			-v css=${abs_top_srcdir}/build-aux/pmccabe.css) \
			> tmp
	mv tmp $@
