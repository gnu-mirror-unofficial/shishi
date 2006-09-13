# Process this file with autoconf to produce a configure script.
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

AC_INIT([shishi], [0.0.27], [bug-shishi@josefsson.org])

# Library code modified:                              REVISION++
# Interfaces changed/added/removed:   CURRENT++       REVISION=0
# Interfaces added:                             AGE++
# Interfaces removed:                           AGE=0
AC_SUBST(LT_CURRENT, 0)
AC_SUBST(LT_REVISION, 27)
AC_SUBST(LT_AGE, 0)

AC_PREREQ(2.60)
AM_INIT_AUTOMAKE([1.9 gnits])
AC_CONFIG_HEADERS(config.h)
AB_INIT

# Checks for header files.
AC_PROG_CC
gl_EARLY
AC_HEADER_STDC
AC_CHECK_HEADERS(sys/poll.h sys/time.h \
	netdb.h time.h termios.h signal.h pwd.h errno.h syslog.h \
	locale.h resolv.h fcntl.h \
	arpa/nameser.h arpa/inet.h netinet/in.h netinet/in6.h)

# Checks for programs.
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL
AM_GNU_GETTEXT(external, need-ngettext)
AM_GNU_GETTEXT_VERSION(0.14.1)
AM_MISSING_PROG(PERL, perl, $missing_dir)
AM_MISSING_PROG(HELP2MAN, help2man, $missing_dir)
AM_MISSING_PROG(ASN1PARSER, asn1Parser, $missing_dir)
AM_MISSING_PROG(GENGETOPT, gengetopt, $missing_dir)
AM_MISSING_PROG(DIA, dia, $missing_dir)

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_SIGNAL
AC_HEADER_TIME
AC_CHECK_DECLS(h_errno)

# For libtasn1
AC_CHECK_SIZEOF(unsigned long int, 4)
AC_CHECK_SIZEOF(unsigned int, 4)

# For gnulib stuff in gl/.
libgcrypt=yes
AC_DEFINE(OK_TO_USE_1S_CLOCK, 1, [Define to 1 to make gettime work.])
gl_INIT

# Checks for library functions.
AC_CHECK_FUNCS(signal select ngettext gethostbyname)
AC_CHECK_LIB(resolv, res_query,, AC_MSG_WARN([[no libresolv, SRV RRs not used]]))
AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(syslog, syslog)

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

AC_SUBST(PAMDIR, "\$(exec_prefix)/lib/security")
AC_ARG_WITH(pam-dir,
  AC_HELP_STRING([--with-pam-dir=DIR],
                 [Where to install PAM module [[PREFIX/lib/security]]]),
            [case "${withval}" in
            /*) PAMDIR="${withval}";;
            ./*|../*) AC_MSG_ERROR(Bad value for --with-pam-dir);;
            *)  PAMDIR="\$(exec_prefix)/lib/${withval}";;
            esac])
AC_MSG_NOTICE([PAM installation path $PAMDIR])

# Check for IPv6
AC_ARG_ENABLE(ipv6,
  AC_HELP_STRING([--disable-ipv6], [Don't use IPv6 even if available]))
if test "$enable_ipv6" != "no"; then
  gl_SOCKET_FAMILIES
  enable_ipv6=$gl_cv_socket_ipv6
fi
if test "$enable_ipv6" != "no"; then
  AC_DEFINE(WITH_IPV6, 1, [Define to 1 if you want IPv6.])
else
  AC_MSG_WARN([[IPv6 support is disabled.]])
fi
AC_MSG_CHECKING([if IPv6 should be used])
AC_MSG_RESULT($enable_ipv6)

# Check for idn
AC_ARG_WITH(stringprep,
  AC_HELP_STRING([--without-stringprep],
		[don't use libidn for string processing even if available]),
	stringprep=$withval, stringprep=yes)
if test "$stringprep" != "no"; then
  AC_LIB_HAVE_LINKFLAGS(idn,, [#include <stringprep.h>],
    [stringprep_check_version (0);])
fi
if test "$ac_cv_libidn" != yes; then
  stringprep=no
  AC_MSG_WARN([Libidn not found.  String process disabled.])
fi
AC_MSG_CHECKING([if String processing support via Libidn should be built])
AC_MSG_RESULT($stringprep)

# Check for libtasn1
AC_ARG_WITH(system-asn1,
	AC_HELP_STRING([--with-system-asn1], [Use the system's libtasn1]),
	system_asn1=$withval, system_asn1=yes)
if test "$system_asn1" != "no"; then
  AC_LIB_HAVE_LINKFLAGS(tasn1,, [#include <libtasn1.h>],
    [asn1_find_node (0, 0);])
fi
if test "$ac_cv_libtasn1" = "yes"; then
  system_asn1=yes
else
  system_asn1=no
  LTLIBTASN1="\$(top_builddir)/asn1/libminitasn1.la"
  LIBTASN1_CFLAGS="-I\$(top_srcdir)/asn1"
  AC_SUBST(LIBTASN1_CFLAGS)
  AC_MSG_WARN([Libtasn1 >= 0.3.1 not found. Using included one.])
fi
AC_MSG_CHECKING([whether to use the system's libtasn1])
AC_MSG_RESULT($system_asn1)
AM_CONDITIONAL(ASN1, test "$system_asn1" = "no")

# Check for gnutls.
AC_ARG_ENABLE(starttls,
	AC_HELP_STRING([--disable-starttls], [disable non-standard STARTTLS]),
	starttls=$enableval, starttls=yes)
if test "$starttls" != "no"; then
  AC_LIB_HAVE_LINKFLAGS(gnutls,, [#include <gnutls/gnutls.h>],
    [gnutls_check_version (0);])
  if test "$ac_cv_libgnutls" != yes; then
    starttls=no
    AC_MSG_WARN([GnuTLS not found.  STARTTLS disabled.])
  else
    starttls=yes
  fi
fi
AC_MSG_CHECKING([if non-standard STARTTLS support should be enabled])
AC_MSG_RESULT($starttls)
if test "$starttls" != "no"; then
	AC_DEFINE(USE_STARTTLS, 1, [Define to 1 if you want STARTTLS.])
fi
AM_CONDITIONAL(STARTTLS, test "$starttls" != "no")

# Check for gtk-doc.
GTK_DOC_CHECK(1.1)

# For some systems we know that we have ld_version scripts.
# Use it then as default.
have_ld_version_script=no
case "${host}" in
    *-*-linux*)
        have_ld_version_script=yes
        ;;
    *-*-gnu*)
        have_ld_version_script=yes
        ;;
esac
AC_ARG_ENABLE([ld-version-script],
              AC_HELP_STRING([--enable-ld-version-script],
                             [enable/disable use of linker version script.
                              (default is system dependent)]),
              [have_ld_version_script=$enableval],
              [ : ] )
AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$have_ld_version_script" = "yes")

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
		enable_arcfour=$enableval, enable_arcfour=yes)
AM_CONDITIONAL(ARCFOUR, test "$enable_arcfour" != "no")
if test "$enable_arcfour" != "no"; then
	AC_DEFINE(WITH_ARCFOUR, 1,
			[Define to 1 if you want ARCFOUR {e,cksum}type.])
fi
AC_MSG_CHECKING([if ARCFOUR encryption/checksum type should be used])
AC_MSG_RESULT($enable_arcfour)

AC_SUBST(CONFDIR, "\$(sysconfdir)/\$(PACKAGE)")
AC_ARG_WITH(conf-dir,
            AC_HELP_STRING([--with-conf-dir=DIR],
                           [store configuration in DIR [[PREFIX/etc/shishi]]]),
            [case "${withval}" in
            /*) CONFDIR="${withval}";;
            ./*|../*) AC_MSG_ERROR(Bad value for --with-conf-dir);;
            *)  CONFDIR="\$(sysconfdir)/${withval}";;
            esac])
AC_MSG_NOTICE([configuration files will be stored in $CONFDIR])

AC_SUBST(SKELDIR, "\$(sysconfdir)/\$(PACKAGE)")
AC_ARG_WITH(skel-dir,
            AC_HELP_STRING([--with-skel-dir=DIR],
                           [store template cfg in DIR [[PREFIX/etc/shishi]]]),
            [case "${withval}" in
            /*) SKELDIR="${withval}";;
            ./*|../*) AC_MSG_ERROR(Bad value for --with-skel-dir);;
            *)  SKELDIR="\$(sysconfdir)/${withval}";;
            esac])
AC_MSG_NOTICE([user template configuration file in $SKELDIR])

AC_SUBST(KEYDIR, "\$(sysconfdir)/\$(PACKAGE)")
AC_ARG_WITH(key-dir,
            AC_HELP_STRING([--with-key-dir=DIR],
                           [store host keys in DIR [[PREFIX/etc/shishi]]]),
            [case "${withval}" in
            /*) KEYDIR="${withval}";;
            ./*|../*) AC_MSG_ERROR(Bad value for --with-key-dir);;
            *)  KEYDIR="\$(sysconfdir)/${withval}";;
            esac])
AC_MSG_NOTICE([host keys will be stored in $KEYDIR])

AC_SUBST(DBDIR, "\$(localstatedir)/\$(PACKAGE)")
AC_ARG_WITH(db-dir,
            AC_HELP_STRING([--with-db-dir=DIR],
                           [Shisa database in DIR [[PREFIX/var/shishi]])]),
            [case "${withval}" in
            /*) DBDIR="${withval}";;
            ./*|../*) AC_MSG_ERROR(Bad value for --with-db-dir);;
            *)  DBDIR="\$(localstatedir)/${withval}";;
            esac])
AC_MSG_NOTICE([user database root path $DBDIR])

AC_DEFINE([xalloc_die], [shishi_xalloc_die], [Fix namespace of xalloc_die.])

AC_CONFIG_FILES(Makefile po/Makefile.in \
	asn1/Makefile examples/Makefile \
	lib/Makefile lib/shishi.h db/Makefile src/Makefile tests/Makefile \
	doc/Makefile doc/reference/Makefile \
	extra/Makefile extra/pam_shishi/Makefile extra/rsh-redone/Makefile \
	gl/Makefile shishi.pc shishi.conf shishi.skel shisa.conf)

# We are done
AC_OUTPUT
