dnl Process this file with autoconf to produce a configure script.

dnl Copyright (C) 2002 Simon Josefsson.
dnl
dnl This file is part of Shishi.
dnl
dnl Shishi is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU Lesser General Public License as
dnl published by the Free Software Foundation; either version 2.1 of
dnl the License, or (at your option) any later version.
dnl
dnl Shishi is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU Lesser General Public License for more details.
dnl
dnl You should have received a copy of the GNU Lesser General Public
dnl License along with Shishi; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

AC_PREREQ(2.50)
AC_INIT(shishi, 0.0.0, bug-shishi@josefsson.org)

# Interfaces removed:    CURRENT++, AGE=0, REVISION=0
# Interfaces added:      CURRENT++, AGE++, REVISION=0
# No interfaces changed:                   REVISION++
LT_CURRENT=0
LT_AGE=0
LT_REVISION=0
AC_SUBST(LT_CURRENT)
AC_SUBST(LT_AGE)
AC_SUBST(LT_REVISION)

AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)

# Checks for programs.
AM_GNU_GETTEXT
AM_GNU_GETTEXT_VERSION(0.11.5)
AC_PROG_LIBTOOL
AC_PROG_CC
AM_MISSING_PROG(PERL, perl, $missing_dir)
AM_MISSING_PROG(HELP2MAN, help2man, $missing_dir)
AM_MISSING_PROG(TEXI2PDF, texi2pdf, $missing_dir)
AM_MISSING_PROG(DOCBOOK2TXT, docbook2txt, $missing_dir)
AM_MISSING_PROG(DOCBOOK2HTML, docbook2html, $missing_dir)
AM_MISSING_PROG(DOCBOOK2PS, docbook2ps, $missing_dir)
AM_MISSING_PROG(DOCBOOK2PDF, docbook2pdf, $missing_dir)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h memory.h string.h strings.h sys/socket.h unistd.h])
AC_CHECK_HEADERS(getopt.h unistd.h strings.h netdb.h time.h sys/poll.h \
	sys/time.h sys/types.h sys/select.h sys/socket.h sys/stat.h stdint.h \
	termios.h signal.h)
AC_CHECK_HEADERS(netinet/in.h netinet/in6.h)

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_TYPE_SIGNAL
AC_HEADER_TIME

# Check for IPv6
AC_ARG_ENABLE(ipv6,
  AC_HELP_STRING([--disable-ipv6], [Don't use IPv6 even if available]))
if test "$enable_ipv6" != "no"; then
  enable_ipv6=yes
  AC_CHECK_DECLS([AF_INET6, IN6ADDR_ANY_INIT],,enable_ipv6=no,[
  #ifdef HAVE_SYS_TYPES_H
  #include <sys/types.h>
  #endif
  #ifdef HAVE_SYS_SOCKET_H
  #include <sys/socket.h>
  #endif
  #ifdef HAVE_NETINET_IN_H
  #include <netinet/in.h>
  #endif
  #ifdef HAVE_NETINET_IN6_H
  #include <netinet/in6.h>
  #endif
  ])
  AC_CHECK_TYPE(struct sockaddr_in6,,enable_ipv6=no,[
  #ifdef HAVE_SYS_TYPES_H
  #include <sys/types.h>
  #endif
  #ifdef HAVE_SYS_SOCKET_H
  #include <sys/socket.h>
  #endif
  #ifdef HAVE_NETINET_IN_H
  #include <netinet/in.h>
  #endif
  #ifdef HAVE_NETINET_IN6_H
  #include <netinet/in6.h>
  #endif
  ])
fi
if test "$enable_ipv6" != "no"; then
  AC_DEFINE(WITH_IPV6, 1, [Define to 1 if you want IPv6.])
else
	AC_MSG_WARN([[

IPv6 support is disabled.

]])
fi
AC_MSG_CHECKING([if IPv6 should be used])
AC_MSG_RESULT($enable_ipv6)

# Test if the libc includes a good enough argp.
AC_ARG_WITH(system-argp,
  AC_HELP_STRING([--without-system-argp], [Don't use the system's argp]))
if test "$with_system_argp" != "no" ; then
  AC_LIB_ARGP(,with_system_argp=no)
fi
if test "$with_system_argp" = "no" ; then
  LIBS="$LIBS \$(top_builddir)/argp/libargp.a"
  CFLAGS="$CFLAGS -I\$(top_srcdir)/argp"
  ARGP=argp
fi
AC_SUBST(ARGP)
AC_CONFIG_SUBDIRS(argp)

# Check gdbm
#AC_ARG_WITH(system-gdbm,
#  AC_HELP_STRING([--without-system-gdbm], [Don't use the system's gdbm]))
#if test "$with_system_gdbm" != "no" ; then
#  AC_CHECK_LIB(gdbm, gdbm_open,,with_system_gdbm=no)
#fi
#LIBGDBM=""
#if test "$with_system_gdbm" = "no" ; then
#  LIBGDBM="\$(top_builddir)/gdbm/libgdbm.a"
#  CFLAGS="$CFLAGS -I\$(top_srcdir)/gdbm"
#  GDBM=gdbm
#  AC_SUBST(GDBM)
#fi
#AC_SUBST(LIBGDBM)

# Check for stringprep
AC_ARG_WITH(system-stringprep,
  AC_HELP_STRING([--without-system-stringprep],
		[don't use the system's libstringprep]))
if test "$with_system_stringprep" != "no" ; then
	PKG_CHECK_MODULES(LIBSTRINGPREP, libstringprep >= 0.0.1,
		with_system_stringprep=yes,
		with_system_stringprep=no)
fi
if test "$with_system_stringprep" = "no"; then
	AC_MSG_WARN([[

The system's libstringprep 0.0.02 or later not used. Using copy
distributed with shishi instead.

See <http://josefsson.org/libstringprep/>.

Don't worry.
]])
	STRINGPREP_CFLAGS="-I\$(top_srcdir)/libstringprep"
	STRINGPREP_LIBS="\$(top_builddir)/libstringprep/libstringprep.la"
	STRINGPREP=libstringprep
fi
AC_SUBST(STRINGPREP)
AC_MSG_CHECKING([if system's libstringprep should be used])
AC_MSG_RESULT($with_system_stringprep)
AC_CONFIG_SUBDIRS(libstringprep)

dnl libtasn1 will be built
dnl AC_CHECK_LIB([tasn1], libasn1_strerror,, AC_MSG_ERROR([libtasn1 is required]))
AC_CONFIG_SUBDIRS(asn1)

# Check for libgcrypt
AC_ARG_WITH(system-libgcrypt,
  AC_HELP_STRING([--without-system-libgcrypt],
		[don't use the system's libgcrypt]))
if test "$with_system_libgcrypt" != "no" ; then
	AM_PATH_LIBGCRYPT(1.1.11, [
		LIBGCRYPT_BUILD_LIBS="$LIBGCRYPT_LIBS"
		LIBGCRYPT_BUILD_CFLAGS="$LIBGCRYPT_CFLAGS"
		with_system_libgcrypt=yes
	], [
		with_system_libgcrypt=no
	])
fi
if test "$with_system_libgcrypt" = "no"; then
	AC_MSG_WARN([[

The system's libgcrypt 1.1.11 or later not used. Using copy
distributed with shishi instead.

See <ftp://ftp.gnupg.org/pub/gcrypt/alpha/libgcrypt/>.

Don't worry.
]])
	LIBGCRYPT_BUILD_CFLAGS="-I\$(top_srcdir)/crypto/src"
	LIBGCRYPT_BUILD_LIBS="\$(top_builddir)/crypto/src/libgcrypt.la"
	LIBGCRYPT_CFLAGS=""
	AC_SUBST(LIBGCRYPT_CFLAGS)
	LIBGCRYPT_LIBS="-lgcrypt"
	AC_SUBST(LIBGCRYPT_LIBS)
	CRYPTO=crypto
fi
AC_SUBST(LIBGCRYPT_BUILD_CFLAGS)
AC_SUBST(LIBGCRYPT_BUILD_LIBS)
AC_SUBST(CRYPTO)
AC_MSG_CHECKING([if system's libgcrypt should be used])
AC_MSG_RESULT($with_system_libgcrypt)
AC_CONFIG_SUBDIRS(crypto)

# Checks for library functions.
AC_FUNC_STRFTIME
AC_CHECK_FUNCS(signal select ngettext gethostbyname)
AC_REPLACE_FUNCS(setenv unsetenv strdup memmove memset strcasecmp \
		strerror gethostname)

# Configure extra tools
AC_CONFIG_SUBDIRS(extra/inetutils)

AC_CONFIG_FILES(Makefile intl/Makefile po/Makefile.in m4/Makefile \
	lib/Makefile lib/shishi.h src/Makefile tests/Makefile doc/Makefile \
	extra/Makefile shishi.pc shishi.conf shishi.skel)

# We are done
AC_OUTPUT
