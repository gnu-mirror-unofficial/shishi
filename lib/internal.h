/* internal.h	internal header file for shishi
 * Copyright (C) 2002  Simon Josefsson
 *
 * This file is part of shishi.
 *
 * Shishi is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with shishi; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef _INTERNAL_H
#define _INTERNAL_H

#if HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#if defined HAVE_DECL_H_ERRNO && !HAVE_DECL_H_ERRNO
extern int h_errno;
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
#  include <stdint.h>
# endif
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#if HAVE_STRING_H
# if !STDC_HEADERS && HAVE_MEMORY_H
#  include <memory.h>
# endif
# include <string.h>
#endif
#if HAVE_STRINGS_H
# include <strings.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif

#ifdef ENABLE_NLS
extern char *_shishi_gettext (const char *str);
#define _(String) _shishi_gettext (String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)
#ifndef HAVE_NGETTEXT
#define ngettext(S1, S2, N) ((N) == 1 ? _(S1) : _(S2))
#endif
#endif

#include "setenv.h"
#include "gettext.h"
#include "shishi.h"

#define GENERALIZEDTIME_TIME_LEN 15
#define MAX_KEY_LEN 32
#define MAX_RANDOM_LEN 32
#define MAX_HASH_LEN 32

#define SHISHI_VERBOSE_CRYPTO  (1<<1)
#define SHISHI_VERBOSE_ASN1    (1<<2)
#define SHISHI_VERBOSE_NOICE   (1<<3)

#define KRBTGT "krbtgt"
#define PRINCIPAL_DELIMITER "/"

#define VERBOSEASN1(h) (h->verbose & SHISHI_VERBOSE_ASN1)
#define VERBOSECRYPTO(h) (h->verbose & SHISHI_VERBOSE_CRYPTO)
#define VERBOSENOICE(h) (h->verbose & SHISHI_VERBOSE_NOICE)
#define VERBOSES (SHISHI_VERBOSE_ASN1 |		\
		  SHISHI_VERBOSE_CRYPTO |	\
		  SHISHI_VERBOSE_NOICE)
#define VERBOSE(h) (h->verbose & ~VERBOSES)

struct Shishi_kdcinfo
{
  char *name;
  struct sockaddr sockaddress;
};

struct Shishi_realminfo
{
  char *name;
  struct Shishi_kdcinfo *kdcaddresses;
  int nkdcaddresses;
};

struct Shishi
{
  ASN1_TYPE asn1;
  int verbose;
  char *default_realm;
  char *default_principal;
  int kdctimeout;
  int kdcretries;
  int *clientkdcetypes;
  int nclientkdcetypes;
  struct Shishi_realminfo *realminfos;
  int nrealminfos;
  char *kdc;
  char error[1024];
  char *gztime_buf[40];
  char *usercfgfile;
  char *ticketsetfile;
  char *stringprocess;
  Shishi_ticketset *ticketset;
  /* XXX remove these: */
  ASN1_TYPE lastauthenticator;
  ASN1_TYPE lastapreq;
  ASN1_TYPE lastaprep;
  ASN1_TYPE lastencapreppart;
};

#define BASE_DIR "/.shishi"
#define TICKET_FILE BASE_DIR "/tickets"
#define USERCFG_FILE BASE_DIR "/config"

/* asn1.c */
int
_shishi_asn1_field (Shishi * handle,
		    ASN1_TYPE node, char *data, int *datalen, char *field);
int
_shishi_asn1_optional_field (Shishi * handle,
			     ASN1_TYPE node,
			     char *data, int *datalen, char *field);
extern ASN1_TYPE
shishi_der2asn1_ticket (ASN1_TYPE definitions,
			char *der, int der_len, char *errorDescription);

int
shishi_format_principal_name (Shishi * handle,
			      ASN1_TYPE namenode,
			      char *namefield,
			      ASN1_TYPE realmnode,
			      char *realmfield, char *out, int *outlen);

ASN1_TYPE
shishi_der2asn1_authenticator (ASN1_TYPE definitions,
			       char *der,
			       int der_len, char *errorDescription);
int
_shishi_print_armored_data (Shishi * handle,
			    FILE * fh,
			    ASN1_TYPE asn1, char *asn1type, char *headers);
int
_shishi_save_data (Shishi * handle, FILE * fh, ASN1_TYPE asn1,
		   char *asn1type);

int
_shishi_authenticator_input (Shishi * handle,
			     FILE * fh, ASN1_TYPE * authenticator, int type);

int
_shishi_apreq_input (Shishi * handle, FILE * fh, ASN1_TYPE * apreq, int type);
int
_shishi_kdcreq_input (Shishi * handle,
		      FILE * fh, ASN1_TYPE * asreq, int type);
int
_shishi_kdcrep_input (Shishi * handle,
		      FILE * fh, ASN1_TYPE * asrep, int type);

#endif /* _INTERNAL_H */
