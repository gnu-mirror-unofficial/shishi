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
# This file represents the specification of how gnulib-tool is used.
# It acts as a cache: It is written and read by gnulib-tool.
# In projects using CVS, this file is meant to be stored in CVS,
# like the configure.ac and various Makefile.am files.


# Specification in the form of a command-line invocation:
#   gnulib-tool --import --dir=. --local-dir=gl/override --lib=libgnu --source-base=gl --m4-base=gl/m4 --doc-base=doc --aux-dir=build-aux --avoid=xalloc-die --libtool --macro-prefix=gl arpa_inet base64 crc crypto/arcfour crypto/gc-des crypto/gc-hmac-md5 crypto/gc-hmac-sha1 crypto/gc-md4 crypto/gc-md5 crypto/gc-pbkdf2-sha1 crypto/gc-random fdl gendocs getaddrinfo getdate getline getpass getsubopt gnupload gpl-3.0 maintainer-makefile netinet_in read-file signal socklen stdint strcase strchrnul strdup strndup strtok_r strverscmp sys_select sys_socket sys_stat sys_time time timegm unistd vasnprintf vasprintf xalloc xgetdomainname xgethostname xstrndup xvasprintf

# Specification in the form of a few gnulib-tool.m4 macro invocations:
gl_LOCAL_DIR([gl/override])
gl_MODULES([arpa_inet base64 crc crypto/arcfour crypto/gc-des crypto/gc-hmac-md5 crypto/gc-hmac-sha1 crypto/gc-md4 crypto/gc-md5 crypto/gc-pbkdf2-sha1 crypto/gc-random fdl gendocs getaddrinfo getdate getline getpass getsubopt gnupload gpl-3.0 maintainer-makefile netinet_in read-file signal socklen stdint strcase strchrnul strdup strndup strtok_r strverscmp sys_select sys_socket sys_stat sys_time time timegm unistd vasnprintf vasprintf xalloc xgetdomainname xgethostname xstrndup xvasprintf])
gl_AVOID([xalloc-die])
gl_SOURCE_BASE([gl])
gl_M4_BASE([gl/m4])
gl_PO_BASE([])
gl_DOC_BASE([doc])
gl_TESTS_BASE([gl/tests])
gl_LIB([libgnu])
gl_MAKEFILE_NAME([])
gl_LIBTOOL
gl_MACRO_PREFIX([gl])
gl_PO_DOMAIN([])
