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

EXTRA_DIST = README

noinst_LTLIBRARIES = libnettle.la

INCLUDES = -I../lib

libnettle_la_SOURCES = macros.h nettle-meta.h nettle-internal.h \
	keymap.h rotors.h parity.h \
	memxor.c memxor.h \
	md4.h md4.c md4-meta.c md5.h md5.c md5-meta.c \
	sha.h sha1.c sha1-compress.c sha1-meta.c \
	hmac.c hmac.h hmac-md5.c hmac-sha1.c \
	arcfour.h arcfour.c arcfour-crypt.c \
	des3.c des.c des.h desCode.h \
	aes.h aes.c aes-internal.h \
	aes-encrypt.c aes-encrypt-table.c aes-decrypt.c aes-decrypt-table.c \
	aes-set-encrypt-key.c aes-set-decrypt-key.c \
	cbc.h cbc.c cbc-cts.h cbc-cts.c cbc-mac.h cbc-mac.c
