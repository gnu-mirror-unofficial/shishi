dnl Process this file with autoconf to produce a configure script.
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
AC_PROG_LIBTOOL
AC_PROG_CC
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_RANLIB
AM_MISSING_PROG(PERL, perl, $missing_dir)
AM_MISSING_PROG(HELP2MAN, help2man, $missing_dir)
AM_MISSING_PROG(TEXI2PDF, texi2pdf, $missing_dir)
AM_MISSING_PROG(DOCBOOK2TXT, docbook2txt, $missing_dir)
AM_MISSING_PROG(DOCBOOK2HTML, docbook2html, $missing_dir)
AM_MISSING_PROG(DOCBOOK2PS, docbook2ps, $missing_dir)
AM_MISSING_PROG(DOCBOOK2PDF, docbook2pdf, $missing_dir)

dnl libtasn1 will be built
dnl AC_CHECK_LIB([tasn1], libasn1_strerror,, AC_MSG_ERROR([libtasn1 is required]))

#AM_PATH_LIBGCRYPT(1.1.9, [
#	LIBGCRYPT="$LIBGCRYPT_LIBS"
#	AC_SUBST(LIBGCRYPT)
#], [
#	AC_MSG_WARN([[
#
#libgcrypt 1.1.9 or later (see ftp://ftp.gnupg.org/pub/gcrypt/alpha/libgcrypt/)
#not installed/working. Using copy distributed with shishi instead.
#
#Don't worry.
#]])
	CRYPTO=crypto
	AC_SUBST(CRYPTO)
	LIBGCRYPT_BUILD_CFLAGS="-I\$(top_srcdir)/crypto/src"
	AC_SUBST(LIBGCRYPT_BUILD_CFLAGS)
	LIBGCRYPT_BUILD_LIBS="\$(top_builddir)/crypto/src/libgcrypt.la"
	AC_SUBST(LIBGCRYPT_BUILD_LIBS)
	LIBGCRYPT_CFLAGS=""
	AC_SUBST(LIBGCRYPT_CFLAGS)
	LIBGCRYPT_LIBS="-lgcrypt"
	AC_SUBST(LIBGCRYPT_LIBS)
#])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h memory.h string.h strings.h sys/socket.h unistd.h])
AC_FUNC_ALLOCA
AC_FUNC_MALLOC

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_C_BIGENDIAN
AC_PROG_GCC_TRADITIONAL
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_TYPE_SIGNAL
AC_HEADER_TIME
AC_HEADER_STDC
AC_CHECK_HEADERS(getopt.h unistd.h strings.h netdb.h time.h sys/poll.h \
	sys/time.h sys/types.h sys/select.h sys/socket.h sys/stat.h stdint.h \
	termios.h signal.h)
AC_CHECK_HEADERS(argp.h)
AC_CHECK_HEADERS(netinet/in.h netinet/in6.h)

# Test if the libc includes a good enough argp.
AC_ARG_WITH(system-argp,
  AC_HELP_STRING([--without-system-argp], [Don't use the system's argp]))
if test "$with_system_argp" != "no" ; then
  AC_LIB_ARGP(,with_system_argp=no)
fi
LIBARGP=""
if test "$with_system_argp" = "no" ; then
  LIBARGP="\$(top_builddir)/argp/libargp.a"
  CFLAGS="$CFLAGS -I\$(top_srcdir)/argp"
  ARGPP=argp
  AC_SUBST(ARGP)
fi
AC_SUBST(LIBARGP)

# Check gdbm
AC_ARG_WITH(system-gdbm,
  AC_HELP_STRING([--without-system-gdbm], [Don't use the system's gdbm]))
if test "$with_system_gdbm" != "no" ; then
  AC_CHECK_LIB(gdbm, gdbm_open,,with_system_gdbm=no)
fi
LIBGDBM=""
if test "$with_system_gdbm" = "no" ; then
  LIBGDBM="\$(top_builddir)/gdbm/libgdbm.a"
  CFLAGS="$CFLAGS -I\$(top_srcdir)/gdbm"
  GDBM=gdbm
  AC_SUBST(GDBM)
fi
AC_SUBST(LIBGDBM)

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
fi
AC_MSG_CHECKING([if IPv6 should be used])
AC_MSG_RESULT($enable_ipv6)

# Check for stringprep
AC_ARG_WITH(system-stringprep,
  AC_HELP_STRING([--without-system-stringprep],
		[Don't use the system's libstringprep]))
if test "$with_system_stringprep" != "no" ; then
	PKG_CHECK_MODULES(LIBSTRINGPREP, libstringprep >= 0.0.0,
		with_system_stringprep=yes,
		with_system_stringprep=no)
fi
if test "$with_system_stringprep" = "no"; then
	AC_MSG_WARN([[

libstringprep 0.0.0 or later (see http://josefsson.org/libstringprep/)
not used, instead shishi falls back to treating principal and username
as strings encoded in the system locale, and stores them into the
KerberosString ASN.1 type without any processing.  This violates
various standards but may work in practice (especially if your system
locale is UTF-8).
]])
fi
AC_MSG_CHECKING([if Stringprep should be used])
AC_MSG_RESULT($with_system_stringprep)

# Checks for library functions.
AC_CHECK_FUNCS(gethostname signal \
		memmove memset bcopy bzero \
		select \
		strchr strdup strerror strstr strcasecmp)
AC_FUNC_STRFTIME

AC_CONFIG_SUBDIRS(asn1 crypto argp gdbm)

AC_CONFIG_FILES(Makefile intl/Makefile po/Makefile.in m4/Makefile \
	lib/Makefile lib/shishi.h src/Makefile tests/Makefile doc/Makefile \
	shishi.pc shishi.conf shishi.skel)

AC_OUTPUT
