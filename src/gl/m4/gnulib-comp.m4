# DO NOT EDIT! GENERATED AUTOMATICALLY!
# Copyright (C) 2002-2021 Free Software Foundation, Inc.
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file.  If not, see <https://www.gnu.org/licenses/>.
#
# As a special exception to the GNU General Public License,
# this file may be distributed as part of a program that
# contains a configuration script generated by Autoconf, under
# the same distribution terms as the rest of that program.
#
# Generated by gnulib-tool.
#
# This file represents the compiled summary of the specification in
# gnulib-cache.m4. It lists the computed macro invocations that need
# to be invoked from configure.ac.
# In projects that use version control, this file can be treated like
# other built files.


# This macro should be invoked from ./configure.ac, in the section
# "Checks for programs", right after AC_PROG_CC, and certainly before
# any checks for libraries, header files, types and library functions.
AC_DEFUN([gl2_EARLY],
[
  m4_pattern_forbid([^gl_[A-Z]])dnl the gnulib macro namespace
  m4_pattern_allow([^gl_ES$])dnl a valid locale name
  m4_pattern_allow([^gl_LIBOBJS$])dnl a variable
  m4_pattern_allow([^gl_LTLIBOBJS$])dnl a variable

  # Pre-early section.
  AC_REQUIRE([gl_PROG_AR_RANLIB])

  # Code from module alloca-opt:
  # Code from module basename-lgpl:
  # Code from module c99:
  # Code from module cloexec:
  # Code from module close:
  # Code from module double-slash-root:
  # Code from module dup2:
  # Code from module errno:
  # Code from module error:
  # Code from module extern-inline:
  # Code from module fcntl:
  # Code from module fcntl-h:
  # Code from module fd-hook:
  # Code from module filename:
  # Code from module fstat:
  # Code from module getdtablesize:
  # Code from module getopt-gnu:
  # Code from module getopt-posix:
  # Code from module getprogname:
  # Code from module largefile:
  AC_REQUIRE([AC_SYS_LARGEFILE])
  # Code from module limits-h:
  # Code from module locale:
  # Code from module malloca:
  # Code from module msvc-inval:
  # Code from module msvc-nothrow:
  # Code from module multiarch:
  # Code from module nocrash:
  # Code from module open:
  # Code from module pathmax:
  # Code from module progname:
  # Code from module snippet/arg-nonnull:
  # Code from module snippet/c++defs:
  # Code from module snippet/warn-on-use:
  # Code from module ssize_t:
  # Code from module stat:
  # Code from module stat-time:
  # Code from module std-gnu11:
  # Code from module stdbool:
  # Code from module stddef:
  # Code from module stdint:
  # Code from module stdio:
  # Code from module strerror:
  # Code from module strerror-override:
  # Code from module sys_stat:
  # Code from module sys_types:
  # Code from module time:
  # Code from module verify:
  # Code from module version-etc:
  # Code from module xalloc-oversized:
])

# This macro should be invoked from ./configure.ac, in the section
# "Check for header files, types and library functions".
AC_DEFUN([gl2_INIT],
[
  AM_CONDITIONAL([GL_COND_LIBTOOL], [true])
  gl_cond_libtool=true
  gl_m4_base='src/gl/m4'
  m4_pushdef([AC_LIBOBJ], m4_defn([gl2_LIBOBJ]))
  m4_pushdef([AC_REPLACE_FUNCS], m4_defn([gl2_REPLACE_FUNCS]))
  m4_pushdef([AC_LIBSOURCES], m4_defn([gl2_LIBSOURCES]))
  m4_pushdef([gl2_LIBSOURCES_LIST], [])
  m4_pushdef([gl2_LIBSOURCES_DIR], [])
  gl_COMMON
  gl_source_base='src/gl'
  gl_FUNC_ALLOCA
  gl_MODULE_INDICATOR_FOR_TESTS([cloexec])
  gl_FUNC_CLOSE
  if test $REPLACE_CLOSE = 1; then
    AC_LIBOBJ([close])
  fi
  gl_UNISTD_MODULE_INDICATOR([close])
  gl_DOUBLE_SLASH_ROOT
  gl_FUNC_DUP2
  if test $REPLACE_DUP2 = 1; then
    AC_LIBOBJ([dup2])
    gl_PREREQ_DUP2
  fi
  gl_UNISTD_MODULE_INDICATOR([dup2])
  gl_HEADER_ERRNO_H
  gl_ERROR
  if test $ac_cv_lib_error_at_line = no; then
    AC_LIBOBJ([error])
    gl_PREREQ_ERROR
  fi
  m4_ifdef([AM_XGETTEXT_OPTION],
    [AM_][XGETTEXT_OPTION([--flag=error:3:c-format])
     AM_][XGETTEXT_OPTION([--flag=error_at_line:5:c-format])])
  AC_REQUIRE([gl_EXTERN_INLINE])
  gl_FUNC_FCNTL
  if test $HAVE_FCNTL = 0 || test $REPLACE_FCNTL = 1; then
    AC_LIBOBJ([fcntl])
  fi
  gl_FCNTL_MODULE_INDICATOR([fcntl])
  gl_FCNTL_H
  gl_FUNC_FSTAT
  if test $REPLACE_FSTAT = 1; then
    AC_LIBOBJ([fstat])
    case "$host_os" in
      mingw*)
        AC_LIBOBJ([stat-w32])
        ;;
    esac
    gl_PREREQ_FSTAT
  fi
  gl_SYS_STAT_MODULE_INDICATOR([fstat])
  gl_FUNC_GETDTABLESIZE
  if test $HAVE_GETDTABLESIZE = 0 || test $REPLACE_GETDTABLESIZE = 1; then
    AC_LIBOBJ([getdtablesize])
    gl_PREREQ_GETDTABLESIZE
  fi
  gl_UNISTD_MODULE_INDICATOR([getdtablesize])
  gl_FUNC_GETOPT_GNU
  dnl Because of the way gl_FUNC_GETOPT_GNU is implemented (the gl_getopt_required
  dnl mechanism), there is no need to do any AC_LIBOBJ or AC_SUBST here; they are
  dnl done in the getopt-posix module.
  gl_FUNC_GETOPT_POSIX
  if test $REPLACE_GETOPT = 1; then
    AC_LIBOBJ([getopt])
    AC_LIBOBJ([getopt1])
    dnl Arrange for unistd.h to include getopt.h.
    GNULIB_GL_GL2_UNISTD_H_GETOPT=1
  fi
  AC_SUBST([GNULIB_GL_GL2_UNISTD_H_GETOPT])
  gl_UNISTD_MODULE_INDICATOR([getopt-posix])
  gl_FUNC_GETPROGNAME
  AC_REQUIRE([gl_LARGEFILE])
  gl_LIMITS_H
  gl_LOCALE_H
  gl_MALLOCA
  AC_REQUIRE([gl_MSVC_INVAL])
  if test $HAVE_MSVC_INVALID_PARAMETER_HANDLER = 1; then
    AC_LIBOBJ([msvc-inval])
  fi
  AC_REQUIRE([gl_MSVC_NOTHROW])
  if test $HAVE_MSVC_INVALID_PARAMETER_HANDLER = 1; then
    AC_LIBOBJ([msvc-nothrow])
  fi
  gl_MODULE_INDICATOR([msvc-nothrow])
  gl_MULTIARCH
  gl_FUNC_OPEN
  if test $REPLACE_OPEN = 1; then
    AC_LIBOBJ([open])
    gl_PREREQ_OPEN
  fi
  gl_FCNTL_MODULE_INDICATOR([open])
  gl_PATHMAX
  AC_CHECK_DECLS([program_invocation_name], [], [], [#include <errno.h>])
  AC_CHECK_DECLS([program_invocation_short_name], [], [], [#include <errno.h>])
  gt_TYPE_SSIZE_T
  gl_FUNC_STAT
  if test $REPLACE_STAT = 1; then
    AC_LIBOBJ([stat])
    case "$host_os" in
      mingw*)
        AC_LIBOBJ([stat-w32])
        ;;
    esac
    gl_PREREQ_STAT
  fi
  gl_SYS_STAT_MODULE_INDICATOR([stat])
  gl_STAT_TIME
  gl_STAT_BIRTHTIME
  AM_STDBOOL_H
  gl_STDDEF_H
  gl_STDINT_H
  gl_STDIO_H
  gl_FUNC_STRERROR
  if test $REPLACE_STRERROR = 1; then
    AC_LIBOBJ([strerror])
  fi
  gl_MODULE_INDICATOR([strerror])
  gl_STRING_MODULE_INDICATOR([strerror])
  AC_REQUIRE([gl_HEADER_ERRNO_H])
  AC_REQUIRE([gl_FUNC_STRERROR_0])
  if test -n "$ERRNO_H" || test $REPLACE_STRERROR_0 = 1; then
    AC_LIBOBJ([strerror-override])
    gl_PREREQ_SYS_H_WINSOCK2
  fi
  gl_HEADER_SYS_STAT_H
  AC_PROG_MKDIR_P
  gl_SYS_TYPES_H
  AC_PROG_MKDIR_P
  gl_HEADER_TIME_H
  gl_VERSION_ETC
  # End of code from modules
  m4_ifval(gl2_LIBSOURCES_LIST, [
    m4_syscmd([test ! -d ]m4_defn([gl2_LIBSOURCES_DIR])[ ||
      for gl_file in ]gl2_LIBSOURCES_LIST[ ; do
        if test ! -r ]m4_defn([gl2_LIBSOURCES_DIR])[/$gl_file ; then
          echo "missing file ]m4_defn([gl2_LIBSOURCES_DIR])[/$gl_file" >&2
          exit 1
        fi
      done])dnl
      m4_if(m4_sysval, [0], [],
        [AC_FATAL([expected source file, required through AC_LIBSOURCES, not found])])
  ])
  m4_popdef([gl2_LIBSOURCES_DIR])
  m4_popdef([gl2_LIBSOURCES_LIST])
  m4_popdef([AC_LIBSOURCES])
  m4_popdef([AC_REPLACE_FUNCS])
  m4_popdef([AC_LIBOBJ])
  AC_CONFIG_COMMANDS_PRE([
    gl2_libobjs=
    gl2_ltlibobjs=
    if test -n "$gl2_LIBOBJS"; then
      # Remove the extension.
      sed_drop_objext='s/\.o$//;s/\.obj$//'
      for i in `for i in $gl2_LIBOBJS; do echo "$i"; done | sed -e "$sed_drop_objext" | sort | uniq`; do
        gl2_libobjs="$gl2_libobjs $i.$ac_objext"
        gl2_ltlibobjs="$gl2_ltlibobjs $i.lo"
      done
    fi
    AC_SUBST([gl2_LIBOBJS], [$gl2_libobjs])
    AC_SUBST([gl2_LTLIBOBJS], [$gl2_ltlibobjs])
  ])
  gltests_libdeps=
  gltests_ltlibdeps=
  m4_pushdef([AC_LIBOBJ], m4_defn([gl2tests_LIBOBJ]))
  m4_pushdef([AC_REPLACE_FUNCS], m4_defn([gl2tests_REPLACE_FUNCS]))
  m4_pushdef([AC_LIBSOURCES], m4_defn([gl2tests_LIBSOURCES]))
  m4_pushdef([gl2tests_LIBSOURCES_LIST], [])
  m4_pushdef([gl2tests_LIBSOURCES_DIR], [])
  gl_COMMON
  gl_source_base='tests'
changequote(,)dnl
  gl2tests_WITNESS=IN_`echo "${PACKAGE-$PACKAGE_TARNAME}" | LC_ALL=C tr abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ | LC_ALL=C sed -e 's/[^A-Z0-9_]/_/g'`_GNULIB_TESTS
changequote([, ])dnl
  AC_SUBST([gl2tests_WITNESS])
  gl_module_indicator_condition=$gl2tests_WITNESS
  m4_pushdef([gl_MODULE_INDICATOR_CONDITION], [$gl_module_indicator_condition])
  m4_popdef([gl_MODULE_INDICATOR_CONDITION])
  m4_ifval(gl2tests_LIBSOURCES_LIST, [
    m4_syscmd([test ! -d ]m4_defn([gl2tests_LIBSOURCES_DIR])[ ||
      for gl_file in ]gl2tests_LIBSOURCES_LIST[ ; do
        if test ! -r ]m4_defn([gl2tests_LIBSOURCES_DIR])[/$gl_file ; then
          echo "missing file ]m4_defn([gl2tests_LIBSOURCES_DIR])[/$gl_file" >&2
          exit 1
        fi
      done])dnl
      m4_if(m4_sysval, [0], [],
        [AC_FATAL([expected source file, required through AC_LIBSOURCES, not found])])
  ])
  m4_popdef([gl2tests_LIBSOURCES_DIR])
  m4_popdef([gl2tests_LIBSOURCES_LIST])
  m4_popdef([AC_LIBSOURCES])
  m4_popdef([AC_REPLACE_FUNCS])
  m4_popdef([AC_LIBOBJ])
  AC_CONFIG_COMMANDS_PRE([
    gl2tests_libobjs=
    gl2tests_ltlibobjs=
    if test -n "$gl2tests_LIBOBJS"; then
      # Remove the extension.
      sed_drop_objext='s/\.o$//;s/\.obj$//'
      for i in `for i in $gl2tests_LIBOBJS; do echo "$i"; done | sed -e "$sed_drop_objext" | sort | uniq`; do
        gl2tests_libobjs="$gl2tests_libobjs $i.$ac_objext"
        gl2tests_ltlibobjs="$gl2tests_ltlibobjs $i.lo"
      done
    fi
    AC_SUBST([gl2tests_LIBOBJS], [$gl2tests_libobjs])
    AC_SUBST([gl2tests_LTLIBOBJS], [$gl2tests_ltlibobjs])
  ])
])

# Like AC_LIBOBJ, except that the module name goes
# into gl2_LIBOBJS instead of into LIBOBJS.
AC_DEFUN([gl2_LIBOBJ], [
  AS_LITERAL_IF([$1], [gl2_LIBSOURCES([$1.c])])dnl
  gl2_LIBOBJS="$gl2_LIBOBJS $1.$ac_objext"
])

# Like AC_REPLACE_FUNCS, except that the module name goes
# into gl2_LIBOBJS instead of into LIBOBJS.
AC_DEFUN([gl2_REPLACE_FUNCS], [
  m4_foreach_w([gl_NAME], [$1], [AC_LIBSOURCES(gl_NAME[.c])])dnl
  AC_CHECK_FUNCS([$1], , [gl2_LIBOBJ($ac_func)])
])

# Like AC_LIBSOURCES, except the directory where the source file is
# expected is derived from the gnulib-tool parameterization,
# and alloca is special cased (for the alloca-opt module).
# We could also entirely rely on EXTRA_lib..._SOURCES.
AC_DEFUN([gl2_LIBSOURCES], [
  m4_foreach([_gl_NAME], [$1], [
    m4_if(_gl_NAME, [alloca.c], [], [
      m4_define([gl2_LIBSOURCES_DIR], [src/gl])
      m4_append([gl2_LIBSOURCES_LIST], _gl_NAME, [ ])
    ])
  ])
])

# Like AC_LIBOBJ, except that the module name goes
# into gl2tests_LIBOBJS instead of into LIBOBJS.
AC_DEFUN([gl2tests_LIBOBJ], [
  AS_LITERAL_IF([$1], [gl2tests_LIBSOURCES([$1.c])])dnl
  gl2tests_LIBOBJS="$gl2tests_LIBOBJS $1.$ac_objext"
])

# Like AC_REPLACE_FUNCS, except that the module name goes
# into gl2tests_LIBOBJS instead of into LIBOBJS.
AC_DEFUN([gl2tests_REPLACE_FUNCS], [
  m4_foreach_w([gl_NAME], [$1], [AC_LIBSOURCES(gl_NAME[.c])])dnl
  AC_CHECK_FUNCS([$1], , [gl2tests_LIBOBJ($ac_func)])
])

# Like AC_LIBSOURCES, except the directory where the source file is
# expected is derived from the gnulib-tool parameterization,
# and alloca is special cased (for the alloca-opt module).
# We could also entirely rely on EXTRA_lib..._SOURCES.
AC_DEFUN([gl2tests_LIBSOURCES], [
  m4_foreach([_gl_NAME], [$1], [
    m4_if(_gl_NAME, [alloca.c], [], [
      m4_define([gl2tests_LIBSOURCES_DIR], [tests])
      m4_append([gl2tests_LIBSOURCES_LIST], _gl_NAME, [ ])
    ])
  ])
])

# This macro records the list of files which have been installed by
# gnulib-tool and may be removed by future gnulib-tool invocations.
AC_DEFUN([gl2_FILE_LIST], [
  lib/alloca.in.h
  lib/arg-nonnull.h
  lib/basename-lgpl.c
  lib/basename-lgpl.h
  lib/c++defs.h
  lib/cloexec.c
  lib/cloexec.h
  lib/close.c
  lib/dup2.c
  lib/errno.in.h
  lib/error.c
  lib/error.h
  lib/fcntl.c
  lib/fcntl.in.h
  lib/fd-hook.c
  lib/fd-hook.h
  lib/filename.h
  lib/fstat.c
  lib/getdtablesize.c
  lib/getopt-cdefs.in.h
  lib/getopt-core.h
  lib/getopt-ext.h
  lib/getopt-pfx-core.h
  lib/getopt-pfx-ext.h
  lib/getopt.c
  lib/getopt.in.h
  lib/getopt1.c
  lib/getopt_int.h
  lib/getprogname.c
  lib/getprogname.h
  lib/limits.in.h
  lib/locale.in.h
  lib/malloca.c
  lib/malloca.h
  lib/msvc-inval.c
  lib/msvc-inval.h
  lib/msvc-nothrow.c
  lib/msvc-nothrow.h
  lib/open.c
  lib/pathmax.h
  lib/progname.c
  lib/progname.h
  lib/stat-time.c
  lib/stat-time.h
  lib/stat-w32.c
  lib/stat-w32.h
  lib/stat.c
  lib/stdbool.in.h
  lib/stddef.in.h
  lib/stdint.in.h
  lib/stdio.in.h
  lib/strerror-override.c
  lib/strerror-override.h
  lib/strerror.c
  lib/sys_stat.in.h
  lib/sys_types.in.h
  lib/time.in.h
  lib/verify.h
  lib/version-etc.c
  lib/version-etc.h
  lib/warn-on-use.h
  lib/xalloc-oversized.h
  m4/00gnulib.m4
  m4/alloca.m4
  m4/close.m4
  m4/double-slash-root.m4
  m4/dup2.m4
  m4/eealloc.m4
  m4/errno_h.m4
  m4/error.m4
  m4/extern-inline.m4
  m4/fcntl-o.m4
  m4/fcntl.m4
  m4/fcntl_h.m4
  m4/fstat.m4
  m4/getdtablesize.m4
  m4/getopt.m4
  m4/getprogname.m4
  m4/gnulib-common.m4
  m4/largefile.m4
  m4/limits-h.m4
  m4/locale_h.m4
  m4/malloca.m4
  m4/mode_t.m4
  m4/msvc-inval.m4
  m4/msvc-nothrow.m4
  m4/multiarch.m4
  m4/nocrash.m4
  m4/off_t.m4
  m4/open-cloexec.m4
  m4/open-slash.m4
  m4/open.m4
  m4/pathmax.m4
  m4/pid_t.m4
  m4/ssize_t.m4
  m4/stat-time.m4
  m4/stat.m4
  m4/std-gnu11.m4
  m4/stdbool.m4
  m4/stddef_h.m4
  m4/stdint.m4
  m4/stdio_h.m4
  m4/strerror.m4
  m4/sys_socket_h.m4
  m4/sys_stat_h.m4
  m4/sys_types_h.m4
  m4/time_h.m4
  m4/unistd_h.m4
  m4/version-etc.m4
  m4/warn-on-use.m4
  m4/wchar_t.m4
  m4/wint_t.m4
  m4/zzgnulib.m4
])
