/* server.c --- Handle KDC sessions.
 * Copyright (C) 2002-2021 Simon Josefsson
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

/* Note: only use syslog to report errors in this file. */

/* Get Shishid stuff. */
#include "kdc.h"

/* Accept new TCP connection in a new listenspec entry. */
static void
kdc_accept (struct listenspec *ls)
{
  struct listenspec *newls;
  struct sockaddr addr;
  socklen_t addrlen;
  int rc;

  newls = xzalloc (sizeof (*newls));
  newls->next = ls->next;
  ls->next = newls;

  newls->bufpos = 0;
  newls->ai.ai_socktype = ls->ai.ai_socktype;
  addrlen = sizeof (addr);
  newls->sockfd = accept (ls->sockfd, &addr, &addrlen);

  rc = getnameinfo (&addr, addrlen,
		    newls->addrname, sizeof (newls->addrname),
		    NULL, 0, NI_NUMERICHOST);
  if (rc != 0)
    strcpy (newls->addrname, "unknown address");
  asprintf (&newls->str, "%s (%s)", newls->addrname, ls->str);

  syslog (LOG_DEBUG | LOG_DAEMON,
	  "Accepted socket %d from socket %d as %s",
	  newls->sockfd, ls->sockfd, newls->str);
}

/* Destroy listenspec element and return pointer to element before the
   removed element, or NULL if the first element was removed (or the
   destroyed list element wasn't in the list). */
static struct listenspec *
kdc_close (struct listenspec *ls)
{
  struct listenspec *tmp;
  int rc;

  syslog (LOG_DEBUG | LOG_DAEMON,
	  "Closing %s socket %d", ls->str, ls->sockfd);

#ifdef USE_STARTTLS
  if (ls->usetls)
    {
      do
	rc = gnutls_bye (ls->session, GNUTLS_SHUT_RDWR);
      while (rc == GNUTLS_E_AGAIN || rc == GNUTLS_E_INTERRUPTED);

      if (rc != GNUTLS_E_SUCCESS)
	syslog (LOG_ERR | LOG_DAEMON,
		"TLS terminate failed to %s on socket %d (%d): %s",
		ls->str, ls->sockfd, rc, gnutls_strerror (rc));

      gnutls_deinit (ls->session);
    }
#endif

  if (ls->sockfd)
    {
      rc = close (ls->sockfd);
      if (rc != 0)
	syslog (LOG_ERR | LOG_DAEMON,
		"Close failed to %s on socket %d (%d): %s",
		ls->str, ls->sockfd, rc, strerror (rc));
    }

  free (ls->str);

  for (tmp = listenspec; tmp && tmp->next != ls; tmp = tmp->next)
    ;
  if (tmp)
    tmp->next = ls->next;

  free (ls);

  return tmp;
}

/* Send string to peer, via UDP/TCP/TLS, reporting any errors. */
void
kdc_send1 (struct listenspec *ls)
{
  ssize_t sent_bytes;

  do
#ifdef USE_STARTTLS
    if (ls->usetls)
      sent_bytes = gnutls_record_send (ls->session, ls->buf, ls->bufpos);
    else
#endif
    if (ls->ai.ai_socktype == SOCK_DGRAM)
      sent_bytes = sendto (ls->sockfd, ls->buf, ls->bufpos, 0,
			   (struct sockaddr *) &ls->udpclientaddr,
			   ls->udpclientaddrlen);
    else
      sent_bytes = send (ls->sockfd, ls->buf, ls->bufpos, 0);
  while (sent_bytes == -1 && errno == EAGAIN);

  if (sent_bytes < 0)
    syslog (LOG_ERR | LOG_DAEMON,
	    "Error writing %zu bytes to %s on socket %d: %s",
	    ls->bufpos, ls->str, ls->sockfd, strerror (errno));
  else if ((size_t) sent_bytes > ls->bufpos)
    syslog (LOG_ERR | LOG_DAEMON,
	    "Overlong write (%zu > %zu) to %s on socket %d",
	    sent_bytes, ls->bufpos, ls->str, ls->sockfd);
  else if ((size_t) sent_bytes < ls->bufpos)
    syslog (LOG_ERR | LOG_DAEMON,
	    "Short write (%zu < %zu) to %s on socket %d",
	    sent_bytes, ls->bufpos, ls->str, ls->sockfd);
}

/* Format response and send it to peer, via UDP/TCP/TLS, reporting any
   errors. */
static void
kdc_send (struct listenspec *ls)
{
  if (ls->ai.ai_socktype == SOCK_DGRAM)
    syslog (LOG_DEBUG | LOG_DAEMON,
	    "Sending %zu bytes to %s socket %d via UDP",
	    ls->bufpos, ls->clientaddrname, ls->sockfd);
  else
    {
      syslog (LOG_DEBUG | LOG_DAEMON,
	      "Sending %zu bytes to %s socket %d via %s",
	      ls->bufpos, ls->str, ls->sockfd, ls->usetls ? "TLS" : "TCP");

      if (ls->bufpos + 4 >= sizeof (ls->buf))
	ls->bufpos = sizeof (ls->buf) - 4;

      memmove (ls->buf + 4, ls->buf, ls->bufpos);
      ls->buf[0] = (ls->bufpos >> 24) & 0xFF;
      ls->buf[1] = (ls->bufpos >> 16) & 0xFF;
      ls->buf[2] = (ls->bufpos >> 8) & 0xFF;
      ls->buf[3] = ls->bufpos & 0xFF;
      ls->bufpos += 4;
    }

  kdc_send1 (ls);

  ls->bufpos = 0;
}

int
kdc_extension_reject (struct listenspec *ls)
{
  Shishi_asn1 krberr;
  char *der;
  size_t derlen;
  int rc;

  syslog (LOG_NOTICE | LOG_AUTH,
	  "Reject extension from %s on socket %d", ls->str, ls->sockfd);

  krberr = shishi_krberror (handle);
  if (!krberr)
    return SHISHI_MALLOC_ERROR;

  rc = shishi_krberror_errorcode_set (handle, krberr,
				      SHISHI_KRB_ERR_FIELD_TOOLONG);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_krberror_set_etext (handle, krberr, "Extension not supported");
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_krberror_der (handle, krberr, &der, &derlen);
  if (rc != SHISHI_OK)
    return rc;

  if (derlen >= BUFSIZ)
    return -1;

  memcpy (ls->buf, der, derlen);
  ls->bufpos = derlen;

  free (der);

  kdc_send1 (ls);

  return -1;
}

#ifndef USE_STARTTLS
/* Dummy function to replace starttls.c functionality. */
int
kdc_extension (struct listenspec *ls)
{
  if (ls->ai.ai_socktype == SOCK_STREAM
      && ls->bufpos == 4 && ls->buf[0] & 0x80)
    return kdc_extension_reject (ls);
  return 0;
}
#endif

/* Read data from peer, reporting any errors. */
static int
kdc_read (struct listenspec *ls)
{
  ssize_t read_bytes;

#ifdef USE_STARTTLS
  if (ls->usetls)
    read_bytes = gnutls_record_recv (ls->session,
				     ls->buf + ls->bufpos,
				     sizeof (ls->buf) - ls->bufpos);
  else
#endif
  if (ls->ai.ai_socktype == SOCK_DGRAM)
    {
      ls->udpclientaddrlen = sizeof (ls->udpclientaddr);
      read_bytes = recvfrom (ls->sockfd, ls->buf + ls->bufpos,
			     sizeof (ls->buf) - ls->bufpos, 0,
			     (struct sockaddr *) &ls->udpclientaddr,
			     &ls->udpclientaddrlen);
    }
  else
    read_bytes = recv (ls->sockfd, ls->buf + ls->bufpos,
		       sizeof (ls->buf) - ls->bufpos, 0);

  if (read_bytes < 0)
    {
#ifdef USE_STARTTLS
      if (ls->usetls)
	syslog (LOG_ERR | LOG_DAEMON,
		"Corrupt TLS data from %s on socket %d (%zd): %s",
		ls->str, ls->sockfd, read_bytes,
		gnutls_strerror (read_bytes));
      else
#endif
	syslog (LOG_ERR | LOG_DAEMON,
		"Error reading from %s on socket %d (%zd): %s",
		ls->str, ls->sockfd, read_bytes, strerror (read_bytes));
      return -1;
    }

  if (read_bytes == 0 && ls->ai.ai_socktype == SOCK_STREAM)
    {
      syslog (LOG_DEBUG | LOG_DAEMON,
	      "Peer %s disconnected on socket %d\n",
	      ls->str, ls->sockfd);
      return -1;
    }

  ls->bufpos += read_bytes;

  if (ls->ai.ai_socktype == SOCK_DGRAM)
    {
      int rc = getnameinfo ((struct sockaddr *) &ls->udpclientaddr,
			    ls->udpclientaddrlen,
			    ls->clientaddrname, sizeof (ls->clientaddrname),
			    NULL, 0, NI_NUMERICHOST);
      if (rc != 0)
	strcpy (ls->clientaddrname, "unknown address");

      syslog (LOG_DEBUG | LOG_DAEMON,
	      "Read %zu bytes from %s on socket %d\n",
	      ls->bufpos, ls->clientaddrname, ls->sockfd);
    }
  else
    syslog (LOG_DEBUG | LOG_DAEMON,
	    "Read %zu bytes from %s on socket %d\n",
	    ls->bufpos, ls->str, ls->sockfd);

  return 0;
}

#define C2I(buf) ((buf[3] & 0xFF) |		\
		  ((buf[2] & 0xFF) << 8) |	\
		  ((buf[1] & 0xFF) << 16) |	\
		  ((buf[0] & 0xFF) << 24))

/* Have we read an entire request? */
static int
kdc_ready (struct listenspec *ls)
{
  size_t waitfor = ls->bufpos >= 4 ? C2I (ls->buf) : 4;

  if (ls->ai.ai_socktype == SOCK_DGRAM && ls->bufpos > 0)
    return 1;
  else if (ls->bufpos > 4 && waitfor + 4 == ls->bufpos)
    return 1;

  if (ls->ai.ai_socktype == SOCK_STREAM)
    syslog (LOG_DEBUG | LOG_DAEMON,
	    "Got %zu bytes of %zu bytes from %s on socket %d\n",
	    ls->bufpos, waitfor + 4, ls->str, ls->sockfd);

  return 0;
}

/* Process a request and store reply in same buffer. */
static void
kdc_process (struct listenspec *ls)
{
  char *p;
  ssize_t plen;

  syslog (LOG_DEBUG | LOG_DAEMON,
	  "Processing %zu bytes on socket %d",
	  ls->bufpos, ls->sockfd);

  if (ls->ai.ai_socktype == SOCK_DGRAM)
    plen = process (ls->buf, ls->bufpos, &p);
  else
    plen = process (ls->buf + 4, ls->bufpos - 4, &p);

  if (plen <= 0)
    {
      syslog (LOG_ERR | LOG_DAEMON,
	      "Processing request failed on socket %d", ls->sockfd);
      memcpy (ls->buf, fatal_krberror, fatal_krberror_len);
      ls->bufpos = fatal_krberror_len;
    }
  else
    {
      memcpy (ls->buf, p, plen);
      ls->bufpos = plen;
      free (p);
    }

  syslog (LOG_DEBUG | LOG_DAEMON,
	  "Generated %zu bytes response for socket %d",
	  ls->bufpos, ls->sockfd);
}

int quit = 0;

static void
ctrlc (int signum)
{
  quit = 1;
}

#define MAX(a,b) ((a) > (b) ? (a) : (b))

/* Main KDC logic, loops around select and calls kdc_accept, kdc_read,
   kdc_extension, kdc_process and kdc_send.  This returns when either
   of the signals SIGINT or SIGTERM is received. */
void
kdc_loop (void)
{
  struct listenspec *ls;
  fd_set readfds;
  int maxfd = 0;
  int rc;

  signal (SIGINT, ctrlc);
  signal (SIGTERM, ctrlc);

#ifdef USE_STARTTLS
  syslog (LOG_INFO | LOG_DAEMON, "Starting (GNUTLS `%s')",
	  gnutls_check_version (NULL));
#else
  syslog (LOG_INFO | LOG_DAEMON, "Starting (no TLS)");
#endif

  while (!quit)
    {
      do
	{
	  FD_ZERO (&readfds);
	  maxfd = 0;
	  for (ls = listenspec; ls; ls = ls->next)
	    {
	      if (ls->sockfd > 0)
		{
		  maxfd = MAX (maxfd, ls->sockfd + 1);
		  if (!arg.quiet_flag)
		    syslog (LOG_DEBUG | LOG_DAEMON,
			    "Listening on %s (%s) socket %d\n",
			    ls->str, ls->addrname, ls->sockfd);
		  FD_SET (ls->sockfd, &readfds);
		}
	    }
	}
      while ((rc = select (maxfd, &readfds, NULL, NULL, NULL)) == 0);

      if (rc < 0)
	{
	  if (errno != EINTR)
	    syslog (LOG_ERR | LOG_DAEMON,
		    "Error listening on sockets (%d): %s",
		    rc, strerror (errno));
	  continue;
	}

      for (ls = listenspec; ls; ls = ls->next)
	if (ls->sockfd > 0 && FD_ISSET (ls->sockfd, &readfds))
	  {
	    if (ls->ai.ai_socktype == SOCK_STREAM && ls->listening)
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

  syslog (LOG_INFO | LOG_DAEMON, "Shutting down");
}
