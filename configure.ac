# Process this file with autoconf to produce a configure script.
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

AC_PREREQ(2.50)
AC_INIT(shishi, 0.0.6, bug-shishi@josefsson.org)

# Interfaces removed:    CURRENT++, AGE=0, REVISION=0
# Interfaces added:      CURRENT++, AGE++, REVISION=0
# No interfaces changed:                   REVISION++
LT_CURRENT=0
LT_AGE=0
LT_REVISION=6
AC_SUBST(LT_CURRENT)
AC_SUBST(LT_AGE)
AC_SUBST(LT_REVISION)

AM_INIT_AUTOMAKE(gnits)
AM_CONFIG_HEADER(config.h)

# Checks for header files.
AC_PROG_CC
AC_GNU_SOURCE
gl_USE_SYSTEM_EXTENSIONS
AC_HEADER_STDC
AC_CHECK_HEADERS(stdlib.h string.h strings.h memory.h \
	sys/types.h sys/socket.h sys/poll.h sys/time.h sys/select.h \
	sys/socket.h sys/stat.h \
	unistd.h netdb.h time.h termios.h signal.h pwd.h errno.h syslog.h \
	locale.h resolv.h fcntl.h \
	arpa/nameser.h arpa/inet.h netinet/in.h netinet/in6.h)

# Checks for programs.
AC_PROG_LIBTOOL
AM_GNU_GETTEXT(external)
AM_GNU_GETTEXT_VERSION(0.12.1)
AM_MISSING_PROG(PERL, perl, $missing_dir)
AM_MISSING_PROG(HELP2MAN, help2man, $missing_dir)
AM_MISSING_PROG(ASN1PARSER, asn1Parser, $missing_dir)
AM_WITH_DMALLOC

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_TYPE_SIGNAL
AC_HEADER_TIME
AX_CREATE_STDINT_H(lib/shishi-int.h)
AC_CHECK_DECLS(h_errno)
AC_CHECK_TYPE([socklen_t],, [AC_DEFINE([socklen_t], [size_t],
              [Define to `size_t' if `socklen_t' is missing.])], [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
])
# For libtasn1
AC_CHECK_SIZEOF(unsigned long long, 8)
AC_CHECK_SIZEOF(unsigned long int, 4)
AC_CHECK_SIZEOF(unsigned int, 4)
AC_CHECK_SIZEOF(unsigned short int, 2)
AC_CHECK_SIZEOF(unsigned char, 1)

# Check for PAM
AC_ARG_ENABLE(pam,
  AC_HELP_STRING([--disable-pam], [Don't use PAM even if available]))
if test "$enable_pam" != "no"; then
	AC_CHECK_HEADERS(security/pam_appl.h)
	AC_CHECK_HEADERS(security/pam_modules.h, [], [],
	[
#if HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
])
  AC_CHECK_HEADERS(security/_pam_macros.h)
  enable_pam=$ac_cv_header_security_pam_modules_h
fi
if test "$enable_pam" != "no"; then
	PAM_SHISHI=pam_shishi
else
	AC_MSG_WARN([[The Shishi PAM module will not be built.]])
fi
AC_SUBST(PAM_SHISHI)
AC_MSG_CHECKING([if PAM should be used])
AC_MSG_RESULT($enable_pam)

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
  AC_MSG_WARN([[IPv6 support is disabled.]])
fi
AC_MSG_CHECKING([if IPv6 should be used])
AC_MSG_RESULT($enable_ipv6)

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

# Check for idn
AC_ARG_WITH(stringprep,
  AC_HELP_STRING([--without-stringprep],
		[don't use libidn even if available]))
if test "$with_stringprep" != "no" ; then
	PKG_CHECK_MODULES(LIBIDN, libidn >= 0.1.0,, with_stringprep=no)
fi
if test "$with_stringprep" != "no"; then
	AC_DEFINE(WITH_STRINGPREP, 1, [Define to 1 if you want to use libidn.])
else
	AC_MSG_WARN([[String processing disabled due to no libidn.]])
fi

# Check for libtasn1
AC_ARG_WITH(system-asn1,
	AC_HELP_STRING([--with-system-asn1], [Use the system's libtasn1]),
	system_asn1=$withval, system_asn1=yes)
if test "$system_asn1" != "no"; then
	AC_CHECK_HEADER(libtasn1.h,, system_asn1=no)
fi
if test "$system_asn1" != "no"; then
	AC_CHECK_LIB(tasn1, asn1_check_version, :,
		system_asn1=no
		AC_MSG_WARN([Libtasn1 >=0.2.2 not found. Using included one.]))
fi
AC_MSG_CHECKING([whether to use the system's libtasn1])
AC_MSG_RESULT($system_asn1)
if test "$system_asn1" != "no"; then
 LIBTASN1_LIBS=-ltasn1
else
 ASN1=asn1
 LIBTASN1_LIBS="\$(top_builddir)/asn1/libminitasn1.la"
fi
AC_SUBST(ASN1)
AC_SUBST(LIBTASN1_LIBS)

# Check for libgcrypt
AC_ARG_WITH(libgcrypt,
  AC_HELP_STRING([--with-libgcrypt], [use libgcrypt for low-level crypto]),
  libgcrypt=$withval, libgcrypt=yes)
if test "$libgcrypt" != "no" ; then
	AM_PATH_LIBGCRYPT(1.1.44, :, [
		libgcrypt=no
		AC_MSG_WARN([Libgcrypt >= 1.1.44 not found.])
	])
fi
AC_MSG_CHECKING([whether to use libgcrypt])
AC_MSG_RESULT($libgcrypt)
if test "$libgcrypt" != "no" ; then
	AC_DEFINE(USE_GCRYPT, 1, [Define to 1 if you want to use libgcrypt.])
else
	CRYPTO=crypto
	CRYPTO_CFLAGS="-I\$(top_srcdir)/crypto"
	CRYPTO_LIBS="\$(top_builddir)/crypto/libnettle.la"
fi
AM_CONDITIONAL(LIBGCRYPT, test "$libgcrypt" != "no")
AM_CONDITIONAL(NETTLE, test "$libgcrypt" = "no")
AC_SUBST(CRYPTO)
AC_SUBST(CRYPTO_CFLAGS)
AC_SUBST(CRYPTO_LIBS)

# Check for library
AC_CHECK_LIB(resolv, res_query,, AC_MSG_WARN([[no libresolv, SRV RRs not used]]))
AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(syslog, syslog)

# Check for gnutls.
AC_ARG_ENABLE(tls,
	AC_HELP_STRING([--enable-tls], [enable unfinished TLS support]),
	tls=$enableval, tls=no)
if test "$tls" != "no"; then
	AM_PATH_LIBGNUTLS(0.8.8, tls=yes, tls=no)
fi
if test "$tls" != "no"; then
	AC_DEFINE(USE_GNUTLS, 1, [Define to 1 if you want TLS.])
fi
AC_MSG_CHECKING([if unfinished TLS support should be enabled])
AC_MSG_RESULT($tls)

# For gnulib stuff in gl/.
gl_C_RESTRICT
gl_FUNC_ALLOCA
gl_ARGP
gl_ERROR
gl_EXITFAIL
gl_GETDATE
gl_FUNC_GETHOSTNAME
gl_GETOPT
jm_FUNC_MALLOC
gl_FUNC_MEMMOVE
gl_FUNC_MEMPCPY
gl_FUNC_MEMSET
gl_FUNC_MKTIME
gl_FUNC_TIMEGM
jm_FUNC_REALLOC
gt_FUNC_SETENV
gl_STRCASE
gl_FUNC_STRCHRNUL
gl_FUNC_STRDUP
gl_FUNC_STRERROR
gl_FUNC_STRNDUP
gl_FUNC_STRNLEN
gl_SYSEXITS
jm_FUNC_GLIBC_UNLOCKED_IO
gl_FUNC_VASNPRINTF
gl_FUNC_VASPRINTF
gl_XALLOC
gl_XSTRNDUP
gl_TIME_R

# Checks for library functions.
AC_FUNC_STRFTIME
AC_CHECK_FUNCS(signal select ngettext gethostbyname)

# Check for gtk-doc.
AC_ARG_WITH(html-dir, [  --with-html-dir=PATH path to installed docs ])
if test "x$with_html_dir" = "x" ; then
  HTML_DIR='${datadir}/gtk-doc/html'
else
  HTML_DIR=$with_html_dir
fi
AC_SUBST(HTML_DIR)
AC_CHECK_PROG(GTKDOC, gtkdoc-mkdb, true, false)
gtk_doc_min_version=0.6
if $GTKDOC ; then 
    gtk_doc_version=`gtkdoc-mkdb --version`
    AC_MSG_CHECKING([gtk-doc version ($gtk_doc_version) >= $gtk_doc_min_version])
    if perl <<EOF ; then
      exit (("$gtk_doc_version" =~ /^[[0-9]]+\.[[0-9]]+$/) &&
            ("$gtk_doc_version" >= "$gtk_doc_min_version") ? 0 : 1);
EOF
      AC_MSG_RESULT(yes)
   else
      AC_MSG_RESULT(no)
      GTKDOC=false
   fi
fi

# Let people disable the gtk-doc stuff.
AC_ARG_ENABLE(gtk-doc, [  --enable-gtk-doc  Use gtk-doc to build documentation [default=auto]], enable_gtk_doc="$enableval", enable_gtk_doc=auto)
if test x$enable_gtk_doc = xauto ; then
  if test x$GTKDOC = xtrue ; then
    enable_gtk_doc=yes
  else
    enable_gtk_doc=no 
  fi
fi
AM_CONDITIONAL(ENABLE_GTK_DOC, test x$enable_gtk_doc = xyes)

# Let people enable/disable various encryption/checksum types.
AC_ARG_ENABLE(des, AC_HELP_STRING([--disable-des],
			[disable DES related encryption/checksum types]),
		enable_des=$enableval, enable_des=yes)
AM_CONDITIONAL(DES, test "$enable_des" != "no")
if test "$enable_des" != "no"; then
	AC_DEFINE(WITH_DES, 1, [Define to 1 if you want DES {e,cksum}types.])
fi
AC_MSG_CHECKING([if DES related encryption/checksum types should be used])
AC_MSG_RESULT($enable_des)

AC_ARG_ENABLE(3des, AC_HELP_STRING([--disable-3des],
			[disable 3DES encryption/checksum type]),
		enable_3des=$enableval, enable_3des=yes)
AM_CONDITIONAL(DES3, test "$enable_3des" != "no")
if test "$enable_3des" != "no"; then
	AC_DEFINE(WITH_3DES, 1, [Define to 1 if you want 3DES {e,cksum}type.])
fi
AC_MSG_CHECKING([if 3DES encryption/checksum type should be used])
AC_MSG_RESULT($enable_3des)

AC_ARG_ENABLE(aes, AC_HELP_STRING([--disable-aes],
			[disable AES encryption/checksum types]),
		enable_aes=$enableval, enable_aes=yes)
AM_CONDITIONAL(AES, test "$enable_aes" != "no")
if test "$enable_aes" != "no"; then
	AC_DEFINE(WITH_AES, 1, [Define to 1 if you want AES {e,cksum}types.])
fi
AC_MSG_CHECKING([if AES encryption/checksum types should be used])
AC_MSG_RESULT($enable_aes)

AC_ARG_ENABLE(md, AC_HELP_STRING([--disable-md],
			[disable unkeyed MD4/MD5 checksum types]),
		enable_md=$enableval, enable_md=yes)
AM_CONDITIONAL(MD, test "$enable_md" != "no")
if test "$enable_md" != "no"; then
	AC_DEFINE(WITH_MD, 1, [Define to 1 if you want MD cksumtypes.])
fi
AC_MSG_CHECKING([if unkeyed MD checksum types should be used])
AC_MSG_RESULT($enable_md)

AC_ARG_ENABLE(null, AC_HELP_STRING([--disable-null],
			[disable dummy NULL encryption/checksum type]),
		enable_null=$enableval, enable_null=yes)
AM_CONDITIONAL(NULL, test "$enable_null" != "no")
if test "$enable_null" != "no"; then
	AC_DEFINE(WITH_NULL, 1, [Define to 1 if you want NULL {e,cksum}type.])
fi
AC_MSG_CHECKING([if dummy NULL encryption/checksum type should be used])
AC_MSG_RESULT($enable_null)

AC_ARG_ENABLE(arcfour, AC_HELP_STRING([--disable-arcfour],
			[disable ARCFOUR encryption/checksum type]),
		enable_arcfour=$enableval, enable_arcfour=no)
AM_CONDITIONAL(ARCFOUR, test "$enable_arcfour" != "no")
if test "$enable_arcfour" != "no"; then
	AC_DEFINE(WITH_ARCFOUR, 1,
			[Define to 1 if you want ARCFOUR {e,cksum}type.])
fi
AC_MSG_CHECKING([if ARCFOUR encryption/checksum type should be used])
AC_MSG_RESULT($enable_arcfour)

AC_CONFIG_FILES(Makefile po/Makefile.in m4/Makefile \
	asn1/Makefile crypto/Makefile examples/Makefile \
	lib/Makefile lib/shishi.h src/Makefile tests/Makefile \
	doc/Makefile doc/reference/Makefile doc/man/Makefile \
	extra/Makefile extra/pam_shishi/Makefile extra/rsh-redone/Makefile \
	gl/Makefile gl/m4/Makefile shishi.pc shishi.conf shishi.skel)

# We are done
AC_OUTPUT
