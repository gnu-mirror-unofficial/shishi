/* internal.h --- Internal header file for Shishi.
 * Copyright (C) 2002, 2003, 2004, 2006  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
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
#include <string.h>
#endif

#include <stdbool.h>
#include <stdint.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <sys/socket.h>

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include <unistd.h>

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#if defined HAVE_DECL_H_ERRNO && !HAVE_DECL_H_ERRNO
/*extern int h_errno;*/
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
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

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#include "gettext.h"

#include "vasprintf.h"
#include "xvasprintf.h"
#include "base64.h"
#include "getdate.h"
#include "getline.h"
#include "strtok_r.h"
#include "strfile.h"
#include "time_r.h"
#include "timegm.h"
#include "vasprintf.h"
#include "xalloc.h"
#include "xgethostname.h"
#include "xgetdomainname.h"
#include "xstrndup.h"

#include "shishi.h"

#define _(String) dgettext (PACKAGE, String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

#define MAX_KEY_LEN 32
#define MAX_RANDOM_LEN 32
#define MAX_HASH_LEN 32
#define MAX_CKSUM_LEN 32

#define SHISHI_VERBOSE_NOISE		(1<<1)
#define SHISHI_VERBOSE_ASN1		(1<<2)
#define SHISHI_VERBOSE_CRYPTO		(1<<3)
#define SHISHI_VERBOSE_CRYPTO_NOISE	(1<<4)

#define KRBTGT "krbtgt"
#define PRINCIPAL_DELIMITER "/"

#define VERBOSENOISE(h) (h->verbose & SHISHI_VERBOSE_NOISE)
#define VERBOSEASN1(h) (h->verbose & SHISHI_VERBOSE_ASN1)
#define VERBOSECRYPTO(h) (h->verbose & SHISHI_VERBOSE_CRYPTO)
#define VERBOSECRYPTONOISE(h) (h->verbose & SHISHI_VERBOSE_CRYPTO_NOISE)
#define VERBOSES (SHISHI_VERBOSE_ASN1 |		\
		  SHISHI_VERBOSE_CRYPTO |	\
		  SHISHI_VERBOSE_NOISE |	\
		  SHISHI_VERBOSE_CRYPTO_NOISE)
#define VERBOSE(h) (h->verbose & ~VERBOSES)

/* For resolv.c and netio.c, on old systems. */
#ifndef T_SRV
# define T_SRV (33)
#endif

enum
{
  UDP,
  TCP,
  TLS
};

struct Shishi_kdcinfo
{
  char *name;
  struct sockaddr sockaddress;
  int protocol;
};

struct Shishi_realminfo
{
  char *name;
  struct Shishi_kdcinfo *kdcaddresses;
  size_t nkdcaddresses;
  char **serverwildcards;
  size_t nserverwildcards;
};

struct Shishi
{
  Shishi_asn1 asn1;
  int verbose;
  int outputtype;
  char *default_realm;
  char *default_principal;
  size_t kdctimeout;
  size_t kdcretries;
  int ticketlife;
  int renewlife;
  int32_t *clientkdcetypes;
  size_t nclientkdcetypes;
  int32_t *authorizationtypes;
  size_t nauthorizationtypes;
  struct Shishi_realminfo *realminfos;
  size_t nrealminfos;
  char *kdc;
  char error[1024];
  char gztime_buf[40];
  char *userdirectory;
  char *usercfgfile;
  char *tktsdefaultfile;
  char *hostkeysdefaultfile;
  char *x509certfile;
  char *x509keyfile;
  char *stringprocess;
  Shishi_tkts *tkts;
};

#define TICKETLIFE (60*60*8)	/* Work day */
#define RENEWLIFE (60*60*24*7)	/* Week */

#endif /* _INTERNAL_H */
