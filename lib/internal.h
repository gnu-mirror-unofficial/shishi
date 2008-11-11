/* internal.h --- Internal header file for Shishi.
 * Copyright (C) 2002, 2003, 2004, 2006, 2007, 2008  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#ifndef _INTERNAL_H
#define _INTERNAL_H

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#include <netdb.h>

#if defined HAVE_DECL_H_ERRNO && !HAVE_DECL_H_ERRNO
/*extern int h_errno;*/
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <errno.h>

#include <netinet/in.h>
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#include <arpa/inet.h>

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

#include "xvasprintf.h"
#include "base64.h"
#include "getdate.h"
#include "read-file.h"
#include "timespec.h"
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
  char *ccachedefault;
  char *hostkeysdefaultfile;
  char *x509cafile;
  char *x509certfile;
  char *x509keyfile;
  char *stringprocess;
  Shishi_tkts *tkts;
  shishi_prompt_password_func prompt_passwd;
};

#define TICKETLIFE (60*60*8)	/* Work day */
#define RENEWLIFE (60*60*24*7)	/* Week */

#endif /* _INTERNAL_H */
