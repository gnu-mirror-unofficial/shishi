# strfile.m4 serial 1
dnl Copyright (C) 2002, 2003, 2004, 2005, 2006 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([gl_FUNC_STRFILE],
[
  AC_LIBSOURCES([strfile.c, strfile.h])
  AC_LIBOBJ([strfile])
  gl_PREREQ_STRFILE
])

# Prerequisites of lib/strfile.c.
AC_DEFUN([gl_PREREQ_STRFILE], [:])
