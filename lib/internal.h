/* internal.h	internal header file for shishi
 * Copyright (C) 2002, 2003  Simon Josefsson
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

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#if defined HAVE_DECL_H_ERRNO && !HAVE_DECL_H_ERRNO
//extern int h_errno;
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
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif

#include "gettext.h"

#include "base64.h"
#include "getdate.h"
#include "time_r.h"
#include "timegm.h"
#include "vasprintf.h"
#include "xalloc.h"
#include "xmemdup.h"
#include "xstrndup.h"

#include "shishi.h"

#define _(String) dgettext (PACKAGE, String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

#define GENERALIZEDTIME_TIME_LEN 15
#define MAX_KEY_LEN 32
#define MAX_RANDOM_LEN 32
#define MAX_HASH_LEN 32
#define MAX_CKSUM_LEN 32

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

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX BUFSIZ
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
  char *default_realm;
  char *default_principal;
  size_t kdctimeout;
  size_t kdcretries;
  int ticketlife;
  int renewlife;
  int32_t *clientkdcetypes;
  size_t nclientkdcetypes;
  struct Shishi_realminfo *realminfos;
  size_t nrealminfos;
  char *kdc;
  char error[1024];
  char gztime_buf[40];
  char *userdirectory;
  char *usercfgfile;
  char *tktsdefaultfile;
  char *hostkeysdefaultfile;
  char *stringprocess;
  Shishi_tkts *tkts;
};

#define BASE_DIR "/.shishi"
#define TICKET_FILE BASE_DIR "/tickets"
#define USERCFG_FILE BASE_DIR "/shishi.conf"

#define TICKETLIFE (60*60*8)	/* Work day */
#define RENEWLIFE (60*60*24*7)	/* Week */

extern int _shishi_crypto_init (void);
extern Shishi_asn1 _shishi_asn1_init (void);

int
_shishi_print_armored_data (Shishi * handle,
			    FILE * fh,
			    Shishi_asn1 asn1, char *asn1type, char *headers);
int
_shishi_save_data (Shishi * handle, FILE * fh, Shishi_asn1 asn1,
		   char *asn1type);

int
_shishi_authenticator_input (Shishi * handle,
			     FILE * fh, Shishi_asn1 * authenticator,
			     int type);
int
_shishi_apreq_input (Shishi * handle, FILE * fh, Shishi_asn1 * apreq,
		     int type);
int _shishi_aprep_input (Shishi * handle, FILE * fh, Shishi_asn1 * aprep,
			 int type);
int _shishi_kdcreq_input (Shishi * handle, FILE * fh, Shishi_asn1 * asreq,
			  int type);
int _shishi_kdcrep_input (Shishi * handle, FILE * fh, Shishi_asn1 * asrep,
			  int type);
int _shishi_krberror_input (Shishi * handle, FILE * fh,
			    Shishi_asn1 * krberror, int type);
int _shishi_encapreppart_input (Shishi * handle, FILE * fh,
				Shishi_asn1 * encapreppart, int type);
int _shishi_safe_input (Shishi * handle, FILE * fh,
			Shishi_asn1 * safe, int type);
int _shishi_priv_input (Shishi * handle, FILE * fh,
			Shishi_asn1 * priv, int type);

Shishi_asn1 _shishi_asn1_read (void);
int _shishi_cipher_init (void);

int
shishi_asn1_integer2_field (Shishi * handle,
			    Shishi_asn1 node, unsigned long *i,
			    const char *field);

/* utils.c */
extern void _shishi_escapeprint (const char *str, int len);
extern void _shishi_hexprint (const char *str, int len);
extern void _shishi_binprint (const char *str, int len);
extern void _shishi_bin7print (const char *str, int len);
extern time_t xtime (time_t * t);
extern int xgettimeofday (struct timeval *tv, struct timezone *tz);

extern struct Shishi_realminfo *shishi_realminfo (Shishi * handle,
						  const char *realm);
extern struct Shishi_realminfo *shishi_realminfo_new (Shishi * handle,
						      char *realm);

#if defined(WITH_DMALLOC) && WITH_DMALLOC
#include <dmalloc.h>
#endif

/* older systems might not have these */
#ifndef T_SRV
# define T_SRV (33)
#endif

typedef struct dnshost_st
{
  struct dnshost_st *next;

  unsigned int type;
  unsigned int class;
  unsigned int ttl;

  void *rr;
} *dnshost_t;

typedef struct dns_srv_st
{
  unsigned int priority;
  unsigned int weight;
  unsigned int port;
  unsigned int rweight;

  char name[256];
} *dns_srv_t;

dnshost_t _shishi_resolv (const char *zone, unsigned int type);
void _shishi_resolv_free (dnshost_t dns);

#endif /* _INTERNAL_H */
