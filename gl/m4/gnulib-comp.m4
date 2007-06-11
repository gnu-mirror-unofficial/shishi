# DO NOT EDIT! GENERATED AUTOMATICALLY!
# Copyright (C) 2004-2007 Free Software Foundation, Inc.
#
# This file is free software, distributed under the terms of the GNU
# General Public License.  As a special exception to the GNU General
# Public License, this file may be distributed as part of a program
# that contains a configuration script generated by Autoconf, under
# the same distribution terms as the rest of that program.
#
# Generated by gnulib-tool.
#
# This file represents the compiled summary of the specification in
# gnulib-cache.m4. It lists the computed macro invocations that need
# to be invoked from configure.ac.
# In projects using CVS, this file can be treated like other built files.


# This macro should be invoked from ./configure.ac, in the section
# "Checks for programs", right after AC_PROG_CC, and certainly before
# any checks for libraries, header files, types and library functions.
AC_DEFUN([gl_EARLY],
[
  m4_pattern_forbid([^gl_[A-Z]])dnl the gnulib macro namespace
  m4_pattern_allow([^gl_ES$])dnl a valid locale name
  m4_pattern_allow([^gl_LIBOBJS$])dnl a variable
  m4_pattern_allow([^gl_LTLIBOBJS$])dnl a variable
  AC_REQUIRE([AC_PROG_RANLIB])
  AC_REQUIRE([AC_GNU_SOURCE])
  AC_REQUIRE([gl_USE_SYSTEM_EXTENSIONS])
  AC_REQUIRE([AC_FUNC_FSEEKO])
  dnl Some compilers (e.g., AIX 5.3 cc) need to be in c99 mode
  dnl for the builtin va_copy to work.  With Autoconf 2.60 or later,
  dnl AC_PROG_CC_STDC arranges for this.  With older Autoconf AC_PROG_CC_STDC
  dnl shouldn't hurt, though installers are on their own to set c99 mode.
  AC_REQUIRE([AC_PROG_CC_STDC])
])

# This macro should be invoked from ./configure.ac, in the section
# "Check for header files, types and library functions".
AC_DEFUN([gl_INIT],
[
  m4_pushdef([AC_LIBOBJ], m4_defn([gl_LIBOBJ]))
  m4_pushdef([AC_REPLACE_FUNCS], m4_defn([gl_REPLACE_FUNCS]))
  m4_pushdef([AC_LIBSOURCES], m4_defn([gl_LIBSOURCES]))
  AM_CONDITIONAL([GL_COND_LIBTOOL], [true])
  gl_cond_libtool=true
  gl_source_base='gl'
  gl_FUNC_ALLOCA
  gl_HEADER_ARPA_INET
  AC_PROG_MKDIR_P
  gl_FUNC_BASE64
  gl_CLOCK_TIME
  gl_CRC
  gl_ARCFOUR
  gl_GC
  if test $gl_cond_libtool = false; then
    gl_ltlibdeps="$gl_ltlibdeps $LTLIBGCRYPT"
    gl_libdeps="$gl_libdeps $LIBGCRYPT"
  fi
  gl_GC_DES
  gl_MODULE_INDICATOR([gc-des])
  gl_GC_HMAC_MD5
  gl_MODULE_INDICATOR([gc-hmac-md5])
  gl_GC_HMAC_SHA1
  gl_MODULE_INDICATOR([gc-hmac-sha1])
  gl_GC_MD4
  gl_MODULE_INDICATOR([gc-md4])
  gl_GC_MD5
  gl_MODULE_INDICATOR([gc-md5])
  gl_GC_PBKDF2_SHA1
  gl_GC_RANDOM
  gl_MODULE_INDICATOR([gc-random])
  gl_ERROR
  gl_FLOAT_H
  gl_FUNC_FSEEKO
  gl_STDIO_MODULE_INDICATOR([fseeko])
  gl_GETADDRINFO
  gl_GETDATE
  gl_FUNC_GETDELIM
  gl_FUNC_GETDOMAINNAME
  gl_FUNC_GETHOSTNAME
  gl_FUNC_GETLINE
  gl_GETOPT
  gl_FUNC_GETPASS
  gl_FUNC_GETSUBOPT
  gl_STDLIB_MODULE_INDICATOR([getsubopt])
  AC_SUBST([LIBINTL])
  AC_SUBST([LTLIBINTL])
  gl_GETTIME
  gl_FUNC_GETTIMEOFDAY
  gl_INET_NTOP
  gl_INLINE
  gl_FUNC_LSEEK
  gl_UNISTD_MODULE_INDICATOR([lseek])
  gl_MALLOCA
  gl_FUNC_MKTIME
  gl_HEADER_NETINET_IN
  AC_PROG_MKDIR_P
  gl_FUNC_READ_FILE
  gl_FUNC_READLINK
  gl_UNISTD_MODULE_INDICATOR([readlink])
  AC_FUNC_REALLOC
  gl_FUNC_SETENV
  gl_FUNC_UNSETENV
  gl_SIZE_MAX
  gl_FUNC_SNPRINTF
  gl_STDIO_MODULE_INDICATOR([snprintf])
  gl_TYPE_SOCKLEN_T
  gt_TYPE_SSIZE_T
  gl_STDARG_H
  AM_STDBOOL_H
  gl_STDINT_H
  gl_STDIO_H
  gl_STDLIB_H
  gl_STRCASE
  gl_FUNC_STRCHRNUL
  gl_STRING_MODULE_INDICATOR([strchrnul])
  gl_FUNC_STRDUP
  gl_STRING_MODULE_INDICATOR([strdup])
  gl_HEADER_STRING_H
  gl_FUNC_STRNDUP
  gl_STRING_MODULE_INDICATOR([strndup])
  gl_FUNC_STRNLEN
  gl_STRING_MODULE_INDICATOR([strnlen])
  gl_FUNC_STRTOK_R
  gl_STRING_MODULE_INDICATOR([strtok_r])
  gl_FUNC_STRVERSCMP
  gl_HEADER_SYS_SELECT
  AC_PROG_MKDIR_P
  gl_HEADER_SYS_SOCKET
  AC_PROG_MKDIR_P
  gl_HEADER_SYS_STAT_H
  AC_PROG_MKDIR_P
  gl_HEADER_SYS_TIME_H
  AC_PROG_MKDIR_P
  gl_HEADER_TIME_H
  gl_TIME_R
  gl_FUNC_TIMEGM
  gl_TIMESPEC
  gl_UNISTD_H
  gl_FUNC_VASNPRINTF
  gl_FUNC_VASPRINTF
  gl_STDIO_MODULE_INDICATOR([vasprintf])
  gl_WCHAR_H
  gl_XALLOC
  gl_XSIZE
  gl_XSTRNDUP
  gl_XVASPRINTF
  m4_popdef([AC_LIBSOURCES])
  m4_popdef([AC_REPLACE_FUNCS])
  m4_popdef([AC_LIBOBJ])
  AC_CONFIG_COMMANDS_PRE([
    gl_libobjs=
    gl_ltlibobjs=
    if test -n "$gl_LIBOBJS"; then
      # Remove the extension.
      sed_drop_objext='s/\.o$//;s/\.obj$//'
      for i in `for i in $gl_LIBOBJS; do echo "$i"; done | sed "$sed_drop_objext" | sort | uniq`; do
        gl_libobjs="$gl_libobjs $i.$ac_objext"
        gl_ltlibobjs="$gl_ltlibobjs $i.lo"
      done
    fi
    AC_SUBST([gl_LIBOBJS], [$gl_libobjs])
    AC_SUBST([gl_LTLIBOBJS], [$gl_ltlibobjs])
  ])
])

# Like AC_LIBOBJ, except that the module name goes
# into gl_LIBOBJS instead of into LIBOBJS.
AC_DEFUN([gl_LIBOBJ],
  [gl_LIBOBJS="$gl_LIBOBJS $1.$ac_objext"])

# Like AC_REPLACE_FUNCS, except that the module name goes
# into gl_LIBOBJS instead of into LIBOBJS.
AC_DEFUN([gl_REPLACE_FUNCS],
  [AC_CHECK_FUNCS([$1], , [gl_LIBOBJ($ac_func)])])

# Like AC_LIBSOURCES, except that it does nothing.
# We rely on EXTRA_lib..._SOURCES instead.
AC_DEFUN([gl_LIBSOURCES],
  [])

# This macro records the list of files which have been installed by
# gnulib-tool and may be removed by future gnulib-tool invocations.
AC_DEFUN([gl_FILE_LIST], [
  build-aux/GNUmakefile
  build-aux/config.rpath
  build-aux/gendocs.sh
  build-aux/gnupload
  build-aux/link-warning.h
  build-aux/maint.mk
  doc/fdl.texi
  doc/gendocs_template
  doc/getdate.texi
  lib/alloca_.h
  lib/arcfour.c
  lib/arcfour.h
  lib/asnprintf.c
  lib/asprintf.c
  lib/base64.c
  lib/base64.h
  lib/crc.c
  lib/crc.h
  lib/des.c
  lib/des.h
  lib/error.c
  lib/error.h
  lib/float+.h
  lib/float_.h
  lib/fseeko.c
  lib/gai_strerror.c
  lib/gc-gnulib.c
  lib/gc-libgcrypt.c
  lib/gc-pbkdf2-sha1.c
  lib/gc.h
  lib/getaddrinfo.c
  lib/getaddrinfo.h
  lib/getdate.h
  lib/getdate.y
  lib/getdelim.c
  lib/getdelim.h
  lib/getdomainname.c
  lib/getdomainname.h
  lib/gethostname.c
  lib/getline.c
  lib/getline.h
  lib/getopt.c
  lib/getopt1.c
  lib/getopt_.h
  lib/getopt_int.h
  lib/getpass.c
  lib/getpass.h
  lib/getsubopt.c
  lib/gettext.h
  lib/gettime.c
  lib/gettimeofday.c
  lib/hmac-md5.c
  lib/hmac-sha1.c
  lib/hmac.h
  lib/inet_ntop.c
  lib/inet_ntop.h
  lib/lseek.c
  lib/malloca.c
  lib/malloca.h
  lib/malloca.valgrind
  lib/md4.c
  lib/md4.h
  lib/md5.c
  lib/md5.h
  lib/memxor.c
  lib/memxor.h
  lib/mktime.c
  lib/netinet_in_.h
  lib/printf-args.c
  lib/printf-args.h
  lib/printf-parse.c
  lib/printf-parse.h
  lib/progname.c
  lib/progname.h
  lib/read-file.c
  lib/read-file.h
  lib/readlink.c
  lib/realloc.c
  lib/setenv.c
  lib/setenv.h
  lib/sha1.c
  lib/sha1.h
  lib/size_max.h
  lib/snprintf.c
  lib/stdbool_.h
  lib/stdint_.h
  lib/stdio_.h
  lib/stdlib_.h
  lib/strcasecmp.c
  lib/strchrnul.c
  lib/strdup.c
  lib/string_.h
  lib/strncasecmp.c
  lib/strndup.c
  lib/strnlen.c
  lib/strtok_r.c
  lib/strverscmp.c
  lib/strverscmp.h
  lib/sys_select_.h
  lib/sys_socket_.h
  lib/sys_stat_.h
  lib/sys_time_.h
  lib/time_.h
  lib/time_r.c
  lib/timegm.c
  lib/timespec.h
  lib/unistd_.h
  lib/unsetenv.c
  lib/vasnprintf.c
  lib/vasnprintf.h
  lib/vasprintf.c
  lib/wchar_.h
  lib/xalloc.h
  lib/xasprintf.c
  lib/xgetdomainname.c
  lib/xgetdomainname.h
  lib/xgethostname.c
  lib/xgethostname.h
  lib/xmalloc.c
  lib/xreadlink.c
  lib/xreadlink.h
  lib/xsize.h
  lib/xstrndup.c
  lib/xstrndup.h
  lib/xvasprintf.c
  lib/xvasprintf.h
  m4/absolute-header.m4
  m4/alloca.m4
  m4/arcfour.m4
  m4/arpa_inet_h.m4
  m4/base64.m4
  m4/bison.m4
  m4/clock_time.m4
  m4/crc.m4
  m4/des.m4
  m4/eealloc.m4
  m4/eoverflow.m4
  m4/error.m4
  m4/extensions.m4
  m4/float_h.m4
  m4/fseeko.m4
  m4/gc-des.m4
  m4/gc-hmac-md5.m4
  m4/gc-hmac-sha1.m4
  m4/gc-md4.m4
  m4/gc-md5.m4
  m4/gc-pbkdf2-sha1.m4
  m4/gc-random.m4
  m4/gc.m4
  m4/getaddrinfo.m4
  m4/getdate.m4
  m4/getdelim.m4
  m4/getdomainname.m4
  m4/gethostname.m4
  m4/getline.m4
  m4/getopt.m4
  m4/getpass.m4
  m4/getsubopt.m4
  m4/gettime.m4
  m4/gettimeofday.m4
  m4/gnulib-common.m4
  m4/hmac-md5.m4
  m4/hmac-sha1.m4
  m4/inet_ntop.m4
  m4/inline.m4
  m4/intmax_t.m4
  m4/inttypes_h.m4
  m4/lib-ld.m4
  m4/lib-link.m4
  m4/lib-prefix.m4
  m4/longlong.m4
  m4/lseek.m4
  m4/malloca.m4
  m4/md4.m4
  m4/md5.m4
  m4/memxor.m4
  m4/mktime.m4
  m4/netinet_in_h.m4
  m4/read-file.m4
  m4/readlink.m4
  m4/setenv.m4
  m4/sha1.m4
  m4/size_max.m4
  m4/snprintf.m4
  m4/socklen.m4
  m4/sockpfaf.m4
  m4/ssize_t.m4
  m4/stdarg.m4
  m4/stdbool.m4
  m4/stdint.m4
  m4/stdint_h.m4
  m4/stdio_h.m4
  m4/stdlib_h.m4
  m4/strcase.m4
  m4/strchrnul.m4
  m4/strdup.m4
  m4/string_h.m4
  m4/strndup.m4
  m4/strnlen.m4
  m4/strtok_r.m4
  m4/strverscmp.m4
  m4/sys_select_h.m4
  m4/sys_socket_h.m4
  m4/sys_stat_h.m4
  m4/sys_time_h.m4
  m4/time_h.m4
  m4/time_r.m4
  m4/timegm.m4
  m4/timespec.m4
  m4/tm_gmtoff.m4
  m4/ulonglong.m4
  m4/unistd_h.m4
  m4/vasnprintf.m4
  m4/vasprintf.m4
  m4/wchar.m4
  m4/wchar_t.m4
  m4/wint_t.m4
  m4/xalloc.m4
  m4/xsize.m4
  m4/xstrndup.m4
  m4/xvasprintf.m4
])
