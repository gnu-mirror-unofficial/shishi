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
AC_INIT(shishi, 0.0.1, bug-shishi@josefsson.org)

# Interfaces removed:    CURRENT++, AGE=0, REVISION=0
# Interfaces added:      CURRENT++, AGE++, REVISION=0
# No interfaces changed:                   REVISION++
LT_CURRENT=0
LT_AGE=0
LT_REVISION=1
AC_SUBST(LT_CURRENT)
AC_SUBST(LT_AGE)
AC_SUBST(LT_REVISION)

AM_INIT_AUTOMAKE(gnits)
AM_CONFIG_HEADER(config.h)

# Checks for header files.
AC_PROG_CC
AC_GNU_SOURCE
AC_HEADER_STDC
AC_CHECK_HEADERS([sys/types.h])
AC_CHECK_HEADERS([stdlib.h memory.h string.h strings.h sys/socket.h unistd.h])
AC_CHECK_HEADERS(getopt.h unistd.h strings.h netdb.h time.h sys/poll.h \
	sys/time.h sys/select.h sys/socket.h sys/stat.h stdint.h termios.h \
	signal.h pwd.h errno.h syslog.h locale.h arpa/nameser.h resolv.h)
AC_CHECK_HEADERS(netinet/in.h netinet/in6.h arpa/inet.h inttypes.h)

# Checks for programs.
AC_PROG_LIBTOOL
AM_GNU_GETTEXT(external)
AM_GNU_GETTEXT_VERSION(0.12.1)
AM_MISSING_PROG(PERL, perl, $missing_dir)
AM_MISSING_PROG(HELP2MAN, help2man, $missing_dir)
AM_MISSING_PROG(TEXI2PDF, texi2pdf, $missing_dir)
AM_MISSING_PROG(DOCBOOK2TXT, docbook2txt, $missing_dir)
AM_MISSING_PROG(DOCBOOK2HTML, docbook2html, $missing_dir)
AM_MISSING_PROG(DOCBOOK2PS, docbook2ps, $missing_dir)
AM_MISSING_PROG(DOCBOOK2PDF, docbook2pdf, $missing_dir)
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
AC_ARG_WITH(included-libtasn1,
	AC_HELP_STRING([--with-included-libtasn1], [Use the included libtasn1]),
	minitasn1_enabled=$withval,
	minitasn1_enabled=no
	AC_CHECK_LIB(tasn1, asn1_read_tag, :,
		minitasn1_enabled=yes
		AC_MSG_WARN([Libtasn1 0.2.x not found. Using included one.])))
AC_MSG_CHECKING([whether to use the included tasn1])
AC_MSG_RESULT($minitasn1_enabled)
if test x"$minitasn1_enabled" = xyes; then
 ASN1=asn1
 LIBTASN1_LIBS="-L../asn1 -lminitasn1"
else
 LIBTASN1_LIBS=-ltasn1
fi
AC_SUBST(ASN1)
AC_SUBST(LIBTASN1_LIBS)

# For libtasn1
AC_CHECK_SIZEOF(unsigned long long, 8)
AC_CHECK_SIZEOF(unsigned long int, 4)
AC_CHECK_SIZEOF(unsigned int, 4)
AC_CHECK_SIZEOF(unsigned short int, 2)
AC_CHECK_SIZEOF(unsigned char, 1)

# Check for libgcrypt
AC_ARG_WITH(system-libgcrypt,
  AC_HELP_STRING([--without-system-libgcrypt],
		[don't use the system's libgcrypt]))
if test "$with_system_libgcrypt" != "no" ; then
	AM_PATH_LIBGCRYPT(1.1.42, [
		with_system_libgcrypt=yes
	], [
		with_system_libgcrypt=no
	])
fi
if test "$with_system_libgcrypt" = "no"; then
  AC_MSG_WARN([[

The system's libgcrypt 1.1.42 or later not used.  Using copy distributed
with shishi instead. See <ftp://ftp.gnupg.org/pub/gcrypt/alpha/libgcrypt/>.
]])
  LIBGCRYPT_CFLAGS="-I\$(top_srcdir)/crypto/src -I\$(top_srcdir)/errcrypto/src"
  LIBGCRYPT_LIBS="\$(top_builddir)/crypto/src/libgcrypt.la"
  CRYPTO="errcrypto crypto"
fi
AC_SUBST(LIBGCRYPT_CFLAGS)
AC_SUBST(LIBGCRYPT_LIBS)
AC_SUBST(CRYPTO)
AC_MSG_CHECKING([if system's libgcrypt should be used])
AC_MSG_RESULT($with_system_libgcrypt)
GPG_ERROR_CONFIG=`pwd`/errcrypto/src/gpg-error-config; export GPG_ERROR_CONFIG
enable_ld_version_script=no; export enable_ld_version_script
AC_CONFIG_SUBDIRS(errcrypto crypto)

# Check for resolver.
AC_CHECK_LIB(resolv, res_query,, AC_MSG_WARN([[no libresolv, SRV RRs not used]]))

# For gnulib stuff in gl/.
gl_FUNC_STRNLEN
gl_FUNC_STRNDUP
gl_FUNC_MEMPCPY
gl_FUNC_ALLOCA
gl_ARGP
gl_ERROR
gl_FUNC_GETHOSTNAME
gl_GETOPT
jm_FUNC_MALLOC
gl_FUNC_MEMMOVE
gl_FUNC_MEMSET
jm_FUNC_REALLOC
gt_FUNC_SETENV
gl_STRCASE
gl_FUNC_STRCHRNUL
gl_FUNC_STRDUP
gl_FUNC_STRERROR
gl_SYSEXITS
jm_FUNC_GLIBC_UNLOCKED_IO
gl_FUNC_VASNPRINTF
gl_FUNC_VASPRINTF
gl_XALLOC

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

AC_CONFIG_FILES(Makefile po/Makefile.in m4/Makefile asn1/Makefile \
	lib/Makefile lib/shishi.h src/Makefile tests/Makefile doc/Makefile \
	doc/reference/Makefile extra/Makefile extra/pam_shishi/Makefile \
	gl/Makefile gl/m4/Makefile shishi.pc shishi.conf shishi.skel)

# We are done
AC_OUTPUT
