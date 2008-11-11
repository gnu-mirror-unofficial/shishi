/* kdc.h --- Header file with common definitions for Shishid.
 * Copyright (C) 2002, 2003, 2004, 2006, 2007, 2008  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>

/* Get ssize_t, setuid, read, etc. */
#include <unistd.h>

/* Get gethostbyname, getservbyname. */
#include <netdb.h>

/* Get getpwnam. */
#ifdef HAVE_PWD_H
# include <pwd.h>
#endif

/* For errno. */
#include <errno.h>

/* For select, etc. */
#include <sys/types.h>

/* For select, etc. */
#include <sys/time.h>
#include <time.h>

/* Get select, etc. */
#include <sys/select.h>

/* Get accept, sendto, etc. */
#include <sys/socket.h>

/* Used for the backlog argument to listen. */
#ifndef SOMAXCONN
# define SOMAXCONN INT_MAX
#endif

#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

/* Get signal, etc. */
#include <signal.h>

#include <netinet/in.h>
#ifdef HAVE_NETINET_IN6_H
# include <netinet/in6.h>
#endif

#include <arpa/inet.h>

#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

#ifdef USE_STARTTLS
# include <gnutls/gnutls.h>
# include <gnutls/x509.h>
#endif

/* Setup i18n. */
#include <locale.h>
#include <gettext.h>
#define _(String) gettext (String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

/* Get xmalloc. */
#include "xalloc.h"

/* Shishi and Shisa library. */
#include <shishi.h>
#include <shisa.h>

/* Command line parameter parser via gengetopt. */
#include "shishid_cmd.h"

struct listenspec
{
  char *str;
  int family;
  int listening;
  struct sockaddr listenaddr;
  struct sockaddr addr;
  socklen_t addrlen;
  struct sockaddr_in *sin;
  int port;
  int type;
  int sockfd;
  char buf[BUFSIZ];		/* XXX */
  size_t bufpos;
  int usetls;
#ifdef USE_STARTTLS
  gnutls_session session;
#endif
  struct listenspec *next;
};

extern Shishi *handle;
extern Shisa *dbh;
extern struct gengetopt_args_info arg;
extern struct listenspec *listenspec;
extern char *fatal_krberror;
extern size_t fatal_krberror_len;

#ifdef USE_STARTTLS
#define DH_BITS 1024
extern gnutls_dh_params dh_params;
extern gnutls_anon_server_credentials anoncred;
extern gnutls_certificate_credentials x509cred;
#endif

/* Interface between shishid.c and server.c. */
extern void kdc_loop (void);

/* Interface between server.c and kdc.c. */
extern ssize_t process (const char *in, size_t inlen, char **out);

/* Interface between server.c and starttls.c. */
extern void kdc_send1 (struct listenspec *ls);
extern int kdc_extension (struct listenspec *ls);

/* Interface between shishid.c, server.c and resume.c. */
#ifdef USE_STARTTLS
extern void resume_db_init (size_t nconnections);
extern void resume_db_done (void);
extern int resume_db_store (void *dbf, gnutls_datum key, gnutls_datum data);
extern gnutls_datum resume_db_fetch (void *dbf, gnutls_datum key);
extern int resume_db_delete (void *dbf, gnutls_datum key);
#endif
