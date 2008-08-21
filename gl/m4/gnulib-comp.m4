# DO NOT EDIT! GENERATED AUTOMATICALLY!
# Copyright (C) 2002-2008 Free Software Foundation, Inc.
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
  AB_INIT
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
  AM_CONDITIONAL([GL_COND_LIBTOOL], [true])
  gl_cond_libtool=true
  m4_pushdef([AC_LIBOBJ], m4_defn([gl_LIBOBJ]))
  m4_pushdef([AC_REPLACE_FUNCS], m4_defn([gl_REPLACE_FUNCS]))
  m4_pushdef([AC_LIBSOURCES], m4_defn([gl_LIBSOURCES]))
  m4_pushdef([gl_LIBSOURCES_LIST], [])
  m4_pushdef([gl_LIBSOURCES_DIR], [])
  gl_COMMON
  gl_source_base='gl'
  gl_EOVERFLOW
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
  gl_ENVIRON
  gl_UNISTD_MODULE_INDICATOR([environ])
  gl_FLOAT_H
  gl_FUNC_FSEEKO
  gl_STDIO_MODULE_INDICATOR([fseeko])
  gl_GETADDRINFO
  gl_GETDATE
  gl_FUNC_GETDELIM
  gl_STDIO_MODULE_INDICATOR([getdelim])
  gl_FUNC_GETDOMAINNAME
  gl_FUNC_GETHOSTNAME
  gl_FUNC_GETLINE
  gl_STDIO_MODULE_INDICATOR([getline])
  gl_FUNC_GETPASS
  gl_FUNC_GETSUBOPT
  gl_STDLIB_MODULE_INDICATOR([getsubopt])
  AC_SUBST([LIBINTL])
  AC_SUBST([LTLIBINTL])
  gl_GETTIME
  gl_FUNC_GETTIMEOFDAY
  # Autoconf 2.61a.99 and earlier don't support linking a file only
  # in VPATH builds.  But since GNUmakefile is for maintainer use
  # only, it does not matter if we skip the link with older autoconf.
  # Automake 1.10.1 and earlier try to remove GNUmakefile in non-VPATH
  # builds, so use a shell variable to bypass this.
  GNUmakefile=GNUmakefile
  m4_if(m4_version_compare([2.61a.100],
  	m4_defn([m4_PACKAGE_VERSION])), [1], [],
        [AC_CONFIG_LINKS([$GNUmakefile:$GNUmakefile], [],
  	[GNUmakefile=$GNUmakefile])])
  gl_INET_NTOP
  gl_ARPA_INET_MODULE_INDICATOR([inet_ntop])
  gl_INLINE
  gl_FUNC_LSEEK
  gl_UNISTD_MODULE_INDICATOR([lseek])
  gl_FUNC_MALLOC_POSIX
  gl_STDLIB_MODULE_INDICATOR([malloc-posix])
  gl_MALLOCA
  gl_MINMAX
  gl_FUNC_MKTIME
  gl_HEADER_NETINET_IN
  AC_PROG_MKDIR_P
  gl_FUNC_RAWMEMCHR
  gl_STRING_MODULE_INDICATOR([rawmemchr])
  gl_FUNC_READ_FILE
  gl_FUNC_REALLOC_POSIX
  gl_STDLIB_MODULE_INDICATOR([realloc-posix])
  gl_FUNC_SETENV
  gl_STDLIB_MODULE_INDICATOR([setenv])
  gl_SIGNAL_H
  gl_SIZE_MAX
  gl_FUNC_SNPRINTF
  gl_STDIO_MODULE_INDICATOR([snprintf])
  gl_TYPE_SOCKLEN_T
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
  gl_HEADER_STRINGS_H
  gl_FUNC_STRNDUP
  gl_STRING_MODULE_INDICATOR([strndup])
  gl_FUNC_STRNLEN
  gl_STRING_MODULE_INDICATOR([strnlen])
  gl_FUNC_STRTOK_R
  gl_STRING_MODULE_INDICATOR([strtok_r])
  gl_FUNC_STRVERSCMP
  gl_STRING_MODULE_INDICATOR([strverscmp])
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
  gl_FUNC_UNSETENV
  gl_STDLIB_MODULE_INDICATOR([unsetenv])
  gl_FUNC_VASNPRINTF
  gl_FUNC_VASPRINTF
  gl_STDIO_MODULE_INDICATOR([vasprintf])
  m4_ifdef([AM_XGETTEXT_OPTION],
    [AM_XGETTEXT_OPTION([--flag=asprintf:2:c-format])
     AM_XGETTEXT_OPTION([--flag=vasprintf:2:c-format])])
  gl_WCHAR_H
  gl_XALLOC
  gl_XSIZE
  gl_XSTRNDUP
  gl_XVASPRINTF
  m4_ifdef([AM_XGETTEXT_OPTION],
    [AM_XGETTEXT_OPTION([--flag=xasprintf:1:c-format])])
  m4_ifval(gl_LIBSOURCES_LIST, [
    m4_syscmd([test ! -d ]m4_defn([gl_LIBSOURCES_DIR])[ ||
      for gl_file in ]gl_LIBSOURCES_LIST[ ; do
        if test ! -r ]m4_defn([gl_LIBSOURCES_DIR])[/$gl_file ; then
          echo "missing file ]m4_defn([gl_LIBSOURCES_DIR])[/$gl_file" >&2
          exit 1
        fi
      done])dnl
      m4_if(m4_sysval, [0], [],
        [AC_FATAL([expected source file, required through AC_LIBSOURCES, not found])])
  ])
  m4_popdef([gl_LIBSOURCES_DIR])
  m4_popdef([gl_LIBSOURCES_LIST])
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
  gltests_libdeps=
  gltests_ltlibdeps=
  m4_pushdef([AC_LIBOBJ], m4_defn([gltests_LIBOBJ]))
  m4_pushdef([AC_REPLACE_FUNCS], m4_defn([gltests_REPLACE_FUNCS]))
  m4_pushdef([AC_LIBSOURCES], m4_defn([gltests_LIBSOURCES]))
  m4_pushdef([gltests_LIBSOURCES_LIST], [])
  m4_pushdef([gltests_LIBSOURCES_DIR], [])
  gl_COMMON
  gl_source_base='gl/tests'
  m4_ifval(gltests_LIBSOURCES_LIST, [
    m4_syscmd([test ! -d ]m4_defn([gltests_LIBSOURCES_DIR])[ ||
      for gl_file in ]gltests_LIBSOURCES_LIST[ ; do
        if test ! -r ]m4_defn([gltests_LIBSOURCES_DIR])[/$gl_file ; then
          echo "missing file ]m4_defn([gltests_LIBSOURCES_DIR])[/$gl_file" >&2
          exit 1
        fi
      done])dnl
      m4_if(m4_sysval, [0], [],
        [AC_FATAL([expected source file, required through AC_LIBSOURCES, not found])])
  ])
  m4_popdef([gltests_LIBSOURCES_DIR])
  m4_popdef([gltests_LIBSOURCES_LIST])
  m4_popdef([AC_LIBSOURCES])
  m4_popdef([AC_REPLACE_FUNCS])
  m4_popdef([AC_LIBOBJ])
  AC_CONFIG_COMMANDS_PRE([
    gltests_libobjs=
    gltests_ltlibobjs=
    if test -n "$gltests_LIBOBJS"; then
      # Remove the extension.
      sed_drop_objext='s/\.o$//;s/\.obj$//'
      for i in `for i in $gltests_LIBOBJS; do echo "$i"; done | sed "$sed_drop_objext" | sort | uniq`; do
        gltests_libobjs="$gltests_libobjs $i.$ac_objext"
        gltests_ltlibobjs="$gltests_ltlibobjs $i.lo"
      done
    fi
    AC_SUBST([gltests_LIBOBJS], [$gltests_libobjs])
    AC_SUBST([gltests_LTLIBOBJS], [$gltests_ltlibobjs])
  ])
])

# Like AC_LIBOBJ, except that the module name goes
# into gl_LIBOBJS instead of into LIBOBJS.
AC_DEFUN([gl_LIBOBJ], [
  AS_LITERAL_IF([$1], [gl_LIBSOURCES([$1.c])])dnl
  gl_LIBOBJS="$gl_LIBOBJS $1.$ac_objext"
])

# Like AC_REPLACE_FUNCS, except that the module name goes
# into gl_LIBOBJS instead of into LIBOBJS.
AC_DEFUN([gl_REPLACE_FUNCS], [
  m4_foreach_w([gl_NAME], [$1], [AC_LIBSOURCES(gl_NAME[.c])])dnl
  AC_CHECK_FUNCS([$1], , [gl_LIBOBJ($ac_func)])
])

# Like AC_LIBSOURCES, except the directory where the source file is
# expected is derived from the gnulib-tool parameterization,
# and alloca is special cased (for the alloca-opt module).
# We could also entirely rely on EXTRA_lib..._SOURCES.
AC_DEFUN([gl_LIBSOURCES], [
  m4_foreach([_gl_NAME], [$1], [
    m4_if(_gl_NAME, [alloca.c], [], [
      m4_define([gl_LIBSOURCES_DIR], [gl])
      m4_append([gl_LIBSOURCES_LIST], _gl_NAME, [ ])
    ])
  ])
])

# Like AC_LIBOBJ, except that the module name goes
# into gltests_LIBOBJS instead of into LIBOBJS.
AC_DEFUN([gltests_LIBOBJ], [
  AS_LITERAL_IF([$1], [gltests_LIBSOURCES([$1.c])])dnl
  gltests_LIBOBJS="$gltests_LIBOBJS $1.$ac_objext"
])

# Like AC_REPLACE_FUNCS, except that the module name goes
# into gltests_LIBOBJS instead of into LIBOBJS.
AC_DEFUN([gltests_REPLACE_FUNCS], [
  m4_foreach_w([gl_NAME], [$1], [AC_LIBSOURCES(gl_NAME[.c])])dnl
  AC_CHECK_FUNCS([$1], , [gltests_LIBOBJ($ac_func)])
])

# Like AC_LIBSOURCES, except the directory where the source file is
# expected is derived from the gnulib-tool parameterization,
# and alloca is special cased (for the alloca-opt module).
# We could also entirely rely on EXTRA_lib..._SOURCES.
AC_DEFUN([gltests_LIBSOURCES], [
  m4_foreach([_gl_NAME], [$1], [
    m4_if(_gl_NAME, [alloca.c], [], [
      m4_define([gltests_LIBSOURCES_DIR], [gl/tests])
      m4_append([gltests_LIBSOURCES_LIST], _gl_NAME, [ ])
    ])
  ])
])

# This macro records the list of files which have been installed by
# gnulib-tool and may be removed by future gnulib-tool invocations.
AC_DEFUN([gl_FILE_LIST], [
  build-aux/config.rpath
  build-aux/gendocs.sh
  build-aux/gnupload
  build-aux/link-warning.h
  doc/fdl.texi
  doc/gendocs_template
  doc/getdate.texi
  doc/gpl-3.0.texi
  lib/alloca.in.h
  lib/arcfour.c
  lib/arcfour.h
  lib/arpa_inet.in.h
  lib/asnprintf.c
  lib/asprintf.c
  lib/base64.c
  lib/base64.h
  lib/c-ctype.c
  lib/c-ctype.h
  lib/crc.c
  lib/crc.h
  lib/des.c
  lib/des.h
  lib/float+.h
  lib/float.in.h
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
  lib/getdomainname.c
  lib/getdomainname.h
  lib/gethostname.c
  lib/getline.c
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
  lib/intprops.h
  lib/lseek.c
  lib/malloc.c
  lib/malloca.c
  lib/malloca.h
  lib/malloca.valgrind
  lib/md4.c
  lib/md4.h
  lib/md5.c
  lib/md5.h
  lib/memxor.c
  lib/memxor.h
  lib/minmax.h
  lib/mktime.c
  lib/netinet_in.in.h
  lib/printf-args.c
  lib/printf-args.h
  lib/printf-parse.c
  lib/printf-parse.h
  lib/rawmemchr.c
  lib/rawmemchr.valgrind
  lib/read-file.c
  lib/read-file.h
  lib/realloc.c
  lib/setenv.c
  lib/sha1.c
  lib/sha1.h
  lib/signal.in.h
  lib/size_max.h
  lib/snprintf.c
  lib/stdarg.in.h
  lib/stdbool.in.h
  lib/stdint.in.h
  lib/stdio-impl.h
  lib/stdio.in.h
  lib/stdlib.in.h
  lib/strcasecmp.c
  lib/strchrnul.c
  lib/strchrnul.valgrind
  lib/strdup.c
  lib/string.in.h
  lib/strings.in.h
  lib/strncasecmp.c
  lib/strndup.c
  lib/strnlen.c
  lib/strtok_r.c
  lib/strverscmp.c
  lib/sys_select.in.h
  lib/sys_socket.in.h
  lib/sys_stat.in.h
  lib/sys_time.in.h
  lib/time.in.h
  lib/time_r.c
  lib/timegm.c
  lib/timespec.h
  lib/unistd.in.h
  lib/unsetenv.c
  lib/vasnprintf.c
  lib/vasnprintf.h
  lib/vasprintf.c
  lib/verify.h
  lib/wchar.in.h
  lib/xalloc.h
  lib/xasprintf.c
  lib/xgetdomainname.c
  lib/xgetdomainname.h
  lib/xgethostname.c
  lib/xgethostname.h
  lib/xmalloc.c
  lib/xsize.h
  lib/xstrndup.c
  lib/xstrndup.h
  lib/xvasprintf.c
  lib/xvasprintf.h
  m4/alloca.m4
  m4/arcfour.m4
  m4/arpa_inet_h.m4
  m4/autobuild.m4
  m4/base64.m4
  m4/bison.m4
  m4/clock_time.m4
  m4/crc.m4
  m4/des.m4
  m4/eealloc.m4
  m4/environ.m4
  m4/eoverflow.m4
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
  m4/getpass.m4
  m4/getsubopt.m4
  m4/gettime.m4
  m4/gettimeofday.m4
  m4/gnulib-common.m4
  m4/hmac-md5.m4
  m4/hmac-sha1.m4
  m4/include_next.m4
  m4/inet_ntop.m4
  m4/inline.m4
  m4/intmax_t.m4
  m4/inttypes_h.m4
  m4/lib-ld.m4
  m4/lib-link.m4
  m4/lib-prefix.m4
  m4/longlong.m4
  m4/lseek.m4
  m4/malloc.m4
  m4/malloca.m4
  m4/md4.m4
  m4/md5.m4
  m4/memxor.m4
  m4/minmax.m4
  m4/mktime.m4
  m4/netinet_in_h.m4
  m4/printf.m4
  m4/rawmemchr.m4
  m4/read-file.m4
  m4/realloc.m4
  m4/setenv.m4
  m4/sha1.m4
  m4/signal_h.m4
  m4/size_max.m4
  m4/snprintf.m4
  m4/socklen.m4
  m4/sockpfaf.m4
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
  m4/strings_h.m4
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
  top/GNUmakefile
  top/maint.mk
])
