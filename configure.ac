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

AM_PATH_LIBGCRYPT(1.1.9, [
	LIBGCRYPT="$LIBGCRYPT_LIBS"
	AC_SUBST(LIBGCRYPT)
], [
	AC_MSG_WARN([[

libgcrypt 1.1.9 or later (see ftp://ftp.gnupg.org/pub/gcrypt/alpha/libgcrypt/)
not installed/working. Using copy distributed with shishi instead.

Don't worry.
]])
	CFLAGS="$CFLAGS -I\$(top_srcdir)/crypto/src"
	CRYPTO=crypto
	AC_SUBST(CRYPTO)
	LIBGCRYPT_LIBS=""
	AC_SUBST(LIBGCRYPT_CFLAGS)
	LIBGCRYPT_LIBS="-lgcrypt"
	AC_SUBST(LIBGCRYPT_LIBS)
	LIBGCRYPT="\$(top_builddir)/crypto/src/libgcrypt.la"
	AC_SUBST(LIBGCRYPT)
])

AM_PATH_GNET(1.1.4, [
	AC_DEFINE(HAVE_GNET, 1, [Define if the GNet library is present.])
], [
	AC_MSG_WARN([[

libgnet 1.1.4 or later (see http://www.gnetlibrary.org/) not installed/working.
Using alternate code instead.

Don't worry.
]])
])

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

# Test if the libc includes a good enough argp.
AC_ARG_WITH(system-argp,
  AC_HELP_STRING([--without-system-argp], [Don't use the system's argp]),,
  [with_system_argp=yes])

if test x$with_system_argp = xyes ; then
  AC_LIB_ARGP(,with_system_argp=no)
fi
LIBARGP=""
if test x$with_system_argp = xno ; then
  LIBARGP="\$(top_builddir)/argp/libargp.a"
fi
AC_SUBST(LIBARGP)

# Checks for library functions.
AC_CHECK_FUNCS(gethostname signal \
		memmove memset bcopy bzero \
		select \
		strchr strdup strerror strstr strcasecmp)
AC_FUNC_STRFTIME

AC_CONFIG_SUBDIRS(asn1 crypto argp)

AC_CONFIG_FILES(Makefile intl/Makefile po/Makefile.in m4/Makefile \
	lib/Makefile lib/shishi.h src/Makefile test/Makefile doc/Makefile \
	shishi.pc shishi.conf shishi.skel)

AC_OUTPUT
