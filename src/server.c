/* server.c --- Handle KDC sessions.
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

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>

/* Get setuid, read, etc. */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

/* Get gethostbyname, getservbyname. */
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

/* For select, etc. */
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

/* For select, etc. */
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

/* Get select, etc. */
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

/* Get accept, sendto, etc. */
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

/* Used for the backlog argument to listen. */
#ifndef SOMAXCONN
# define SOMAXCONN INT_MAX
#endif

#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

/* Get errno. */
#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif
#ifndef errno
extern int errno;
#endif

#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
#  include <stdint.h>
# endif
#endif

/* Get signal, etc. */
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
# include <netinet/in6.h>
#endif

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

#ifdef USE_STARTTLS
# include <gnutls/gnutls.h>
#endif

/* Setup i18n. */
#ifdef HAVE_LOCALE_H
# include <locale.h>
#else
# define setlocale(Category, Locale) /* empty */
#endif
#include <gettext.h>
#define _(String) gettext (String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

/* Get xmalloc. */
#include "xalloc.h"

/* Get error. */
#include "error.h"

/* Get asprintf. */
#include "vasprintf.h"

/* Get program_name, etc. */
#include "progname.h"

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
  char buf[BUFSIZ]; /* XXX */
  size_t bufpos;
#ifdef USE_STARTTLS
  gnutls_session session;
  int usetls;
#endif
  struct listenspec *next;
};

extern Shishi * handle;
extern Shisa * dbh;
extern struct gengetopt_args_info arg;
extern struct listenspec *listenspec;
extern char *fatal_krberror;
extern size_t fatal_krberror_len;

#ifdef USE_STARTTLS
#define DH_BITS 1024
extern gnutls_dh_params dh_params;
extern gnutls_anon_server_credentials anoncred;
#endif

extern void process (char *in, int inlen, char **out, size_t * outlen);

/* Destroy listenspec element and return pointer to element before the
   removed element, or NULL if the first element was removed (or the
   destroyed list element wasn't in the list). */
struct listenspec *
kdc_close (struct listenspec *ls)
{
  struct listenspec *tmp;
  int rc;

  if (ls->sockfd)
    {
      if (!arg.quiet_flag)
	printf ("Closing %s...\n", ls->str);
      rc = close (ls->sockfd);
      if (rc != 0)
	syslog (LOG_ERR, "Could not close connection to %s on socket %d",
		ls->str, ls->sockfd);
    }

  if (ls->usetls)
    {
      gnutls_bye (ls->session, GNUTLS_SHUT_WR);
      gnutls_deinit (ls->session);
    }

  if (ls->str)
    free (ls->str);

  for (tmp = listenspec; tmp && tmp->next != ls; tmp = tmp->next)
    ;
  if (tmp)
    tmp->next = ls->next;

  free (ls);

  return tmp;
}

static int
kdc_extension (struct listenspec *ls)
{
  ssize_t sent_bytes, read_bytes;
  int rc;

#ifdef USE_STARTTLS
  if (!ls->usetls &&
      ls->type == SOCK_STREAM &&
      ls->bufpos == 4 &&
      memcmp (ls->buf, "\x70\x00\x00\x01", 4) == 0)
    {
      const int kx_prio[] = { GNUTLS_KX_ANON_DH, 0 };

      if (!arg.quiet_flag)
	printf ("Trying to upgrade to TLS...\n");

      sent_bytes = sendto (ls->sockfd, "\x70\x00\x00\x02", 4,
			   0, &ls->addr, ls->addrlen);

      rc = gnutls_init (&ls->session, GNUTLS_SERVER);
      if (rc != GNUTLS_E_SUCCESS)
	error (EXIT_FAILURE, 0, "gnutls_init %d", rc);
      rc = gnutls_set_default_priority (ls->session);
      if (rc != GNUTLS_E_SUCCESS)
	error (EXIT_FAILURE, 0, "gnutls_sdp %d", rc);
      rc = gnutls_kx_set_priority (ls->session, kx_prio);
      if (rc != GNUTLS_E_SUCCESS)
	error (EXIT_FAILURE, 0, "gnutls_ksp %d", rc);
      rc = gnutls_credentials_set (ls->session, GNUTLS_CRD_ANON,
				   anoncred);
      if (rc != GNUTLS_E_SUCCESS)
	error (EXIT_FAILURE, 0, "gnutls_cs %d", rc);
      gnutls_dh_set_prime_bits (ls->session, DH_BITS);
      gnutls_transport_set_ptr (ls->session,
				(gnutls_transport_ptr)
				ls->sockfd);

      rc = gnutls_handshake (ls->session);
      if (rc < 0)
	{
	  printf ("Handshake has failed %d: %s\n",
		  rc, gnutls_strerror (rc));
	  return -1;
	}

      if (!arg.quiet_flag)
	printf ("TLS successful\n");

      ls->bufpos = 0;
      ls->usetls = 1;
    }
#endif

  return 0;
}

static void
kdc_process (struct listenspec *ls)
{
  ssize_t sent_bytes, read_bytes;
  int rc;
  char *p;
  size_t plen;

#ifdef USE_STARTTLS
  if (ls->usetls)
    {
      process (ls->buf, ls->bufpos, &p, &plen);
      printf ("TLS process %d sending %d\n", ls->bufpos, plen);
    }
  else
#endif
    {
      if (ls->type == SOCK_STREAM)
	process (ls->buf + 4, ls->bufpos - 4, &p, &plen);
      else
	process (ls->buf, ls->bufpos, &p, &plen);
    }

  printf ("Got %d bytes\n", plen);

  memcpy (ls->buf, p, plen);
  ls->bufpos = plen;

  if (p != fatal_krberror)
    free (p);
}

static void
kdc_send (struct listenspec *ls)
{
  ssize_t sent_bytes, read_bytes;
  int rc;

  printf ("Sending %d bytes on socket %d\n", ls->bufpos, ls->sockfd);

#ifdef USE_STARTTLS
  if (ls->usetls)
    {
      printf ("TLS sending %d\n", ls->bufpos);

      sent_bytes = gnutls_record_send (ls->session, ls->buf, ls->bufpos);
    }
  else
#endif
    {
      if (ls->type == SOCK_STREAM)
	{
	  uint32_t len = htonl (ls->bufpos) + 4;

	  do
	    sent_bytes = sendto (ls->sockfd, &len, 4,
				 0, &ls->addr, ls->addrlen);
	  while (sent_bytes == -1 && errno == EAGAIN);
	}

      do
	sent_bytes = sendto (ls->sockfd, ls->buf, ls->bufpos,
			     0, &ls->addr, ls->addrlen);
      while (sent_bytes == -1 && errno == EAGAIN);

      printf ("sent %d\n", sent_bytes);

      if (sent_bytes < 0)
	perror ("write");
      else if ((size_t) sent_bytes > ls->bufpos)
	fprintf (stderr, "wrote %db but buffer only %db",
		 sent_bytes, ls->bufpos);
      else if ((size_t) sent_bytes < ls->bufpos)
	fprintf (stderr,
		 "short write (%db) writing %d bytes\n",
		 sent_bytes, ls->bufpos);
    }

  ls->bufpos = 0;
}

static int
kdc_ready (struct listenspec *ls)
{
  ssize_t sent_bytes, read_bytes;
  int rc;

#ifdef USE_STARTTLS
  if (ls->usetls && ls->bufpos > 0)
    return 1;
  else
#endif
    if (ls->type == SOCK_DGRAM)
      return 1;
    else if (ls->bufpos > 4 && ntohl (*(int *) ls->buf) + 4 == ls->bufpos)
      return 1;

  return 0;
}

static int
kdc_read (struct listenspec *ls)
{
  ssize_t read_bytes;

  ls->addrlen = sizeof (ls->addr);
  if (ls->usetls)
    read_bytes = gnutls_record_recv (ls->session, ls->buf,
				     sizeof (ls->buf));
  else
    read_bytes = recvfrom (ls->sockfd, ls->buf + ls->bufpos,
			   sizeof(ls->buf) - ls->bufpos, 0,
			   &ls->addr, &ls->addrlen);
  if (read_bytes < 0)
    {
      if (ls->usetls)
	error (0, 0, "Corrupted TLS data (%d): %s\n", read_bytes,
	       gnutls_strerror (read_bytes));
      else
	error (0, errno, "Error from recvfrom (%d)", read_bytes);
      return -1;
    }

  if (read_bytes == 0 && ls->type == SOCK_STREAM)
    {
      if (!arg.quiet_flag)
	printf ("Peer %s disconnected\n", ls->str);
      return -1;
    }

  ls->bufpos += read_bytes;

  if (!arg.quiet_flag)
    printf ("Has %d bytes from %s on socket %d\n",
	    ls->bufpos, ls->str, ls->sockfd);

  return 0;
}

static void
kdc_accept (struct listenspec *ls)
{
  struct listenspec *newls;

  newls = xzalloc (sizeof (*newls));
  newls->next = ls->next;
  ls->next = newls;

  newls->bufpos = 0;
  newls->type = ls->type;
  newls->addrlen = sizeof (newls->addr);
  newls->sockfd = accept (ls->sockfd, &newls->addr, &newls->addrlen);
  newls->sin = (struct sockaddr_in *) &newls->addr;
  asprintf (&newls->str, "%s peer %s", ls->str,
	    inet_ntoa (newls->sin->sin_addr));

  if (!arg.quiet_flag)
    printf ("Accepted socket %d from socket %d as %s\n",
	    newls->sockfd, ls->sockfd, newls->str);
}

int quit = 0;

static void
ctrlc (int signum)
{
  quit = 1;
}

#define MAX(a,b) ((a) > (b) ? (a) : (b))

void
kdc_loop (void)
{
  struct listenspec *ls;
  fd_set readfds;
  int maxfd = 0, i;
  int rc;

  signal (SIGINT, ctrlc);
  signal (SIGTERM, ctrlc);

  while (!quit)
    {
      do
	{
	  FD_ZERO (&readfds);
	  maxfd = 0;
	  for (ls = listenspec; ls; ls = ls->next)
	    {
	      maxfd = MAX(maxfd, ls->sockfd + 1);
	      if (!arg.quiet_flag)
		printf ("Listening on socket %d\n", ls->sockfd);
	      FD_SET (ls->sockfd, &readfds);
	    }
	}
      while ((rc = select (maxfd, &readfds, NULL, NULL, NULL)) == 0);

      if (rc < 0)
	{
	  if (errno != EINTR)
	    error (0, errno, "Error listening to sockets (%d)", rc);
	  continue;
	}

      for (ls = listenspec; ls; ls = ls->next)
	if (FD_ISSET (ls->sockfd, &readfds))
	  if (ls->type == SOCK_STREAM && ls->listening)
	    kdc_accept (ls);
	  else if (kdc_read (ls) < 0)
	    ls = kdc_close (ls);
	  else if (kdc_extension (ls) < 0)
	    ls = kdc_close (ls);
	  else if (kdc_ready (ls))
	    {
	      kdc_process (ls);
	      kdc_send (ls);
	    }
    }
}
