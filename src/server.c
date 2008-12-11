/* server.c --- Handle KDC sessions.
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

/* Note: only use syslog to report errors in this file. */

/* Get Shishid stuff. */
#include "kdc.h"

/* Accept new TCP connection in a new listenspec entry. */
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

  syslog (LOG_DEBUG, "Accepted socket %d from socket %d as %s",
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

  syslog (LOG_INFO, "Closing %s socket %d", ls->str, ls->sockfd);

#ifdef USE_STARTTLS
  if (ls->usetls)
    {
      do
	rc = gnutls_bye (ls->session, GNUTLS_SHUT_RDWR);
      while (rc == GNUTLS_E_AGAIN || rc == GNUTLS_E_INTERRUPTED);

      if (rc != GNUTLS_E_SUCCESS)
	syslog (LOG_ERR, "TLS terminate failed to %s on socket %d (%d): %s",
		ls->str, ls->sockfd, rc, gnutls_strerror (rc));

      gnutls_deinit (ls->session);
    }
#endif

  if (ls->sockfd)
    {
      rc = close (ls->sockfd);
      if (rc != 0)
	syslog (LOG_ERR, "Close failed to %s on socket %d (%d): %s",
		ls->str, ls->sockfd, rc, strerror (rc));
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
      sent_bytes = sendto (ls->sockfd, ls->buf, ls->bufpos,
			   0, &ls->addr, ls->addrlen);
  while (sent_bytes == -1 && errno == EAGAIN);

  if (sent_bytes < 0)
    syslog (LOG_ERR, "Error writing %d bytes to %s on socket %d: %s",
	    ls->bufpos, ls->str, ls->sockfd, strerror (errno));
  else if ((size_t) sent_bytes > ls->bufpos)
    syslog (LOG_ERR, "Overlong write (%d > %d) to %s on socket %d",
	    sent_bytes, ls->bufpos, ls->str, ls->sockfd);
  else if ((size_t) sent_bytes < ls->bufpos)
    syslog (LOG_ERR, "Short write (%d < %d) to %s on socket %d",
	    sent_bytes, ls->bufpos, ls->str, ls->sockfd);
}

/* Format response and send it to peer, via UDP/TCP/TLS, reporting any
   errors. */
static void
kdc_send (struct listenspec *ls)
{
  if (ls->type == SOCK_DGRAM)
    syslog (LOG_DEBUG, "Sending %d bytes to %s socket %d via UDP",
	    ls->bufpos, ls->str, ls->sockfd);
  else
    {
      syslog (LOG_DEBUG, "Sending %d bytes to %s socket %d via %s",
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

#ifndef USE_STARTTLS
/* Dummy function to replace starttls.c functionality. */
int
kdc_extension (struct listenspec *ls)
{
  return 0;
}
#endif

/* Read data from peer, reporting any errors. */
static int
kdc_read (struct listenspec *ls)
{
  ssize_t read_bytes;

  ls->addrlen = sizeof (ls->addr);
#ifdef USE_STARTTLS
  if (ls->usetls)
    read_bytes = gnutls_record_recv (ls->session,
				     ls->buf + ls->bufpos,
				     sizeof (ls->buf) - ls->bufpos);
  else
#endif
    read_bytes = recvfrom (ls->sockfd, ls->buf + ls->bufpos,
			   sizeof (ls->buf) - ls->bufpos, 0,
			   &ls->addr, &ls->addrlen);
  if (read_bytes < 0)
    {
#ifdef USE_STARTTLS
      if (ls->usetls)
	syslog (LOG_ERR, "Corrupt TLS data from %s on socket %d (%d): %s",
		ls->str, ls->sockfd, read_bytes,
		gnutls_strerror (read_bytes));
      else
#endif
	syslog (LOG_ERR, "Error reading from %s on socket %d (%d): %s",
		ls->str, ls->sockfd, read_bytes, strerror (read_bytes));
      return -1;
    }

  if (read_bytes == 0 && ls->type == SOCK_STREAM)
    {
      syslog (LOG_DEBUG, "Peer %s disconnected on socket %d\n",
	      ls->str, ls->sockfd);
      return -1;
    }

  ls->bufpos += read_bytes;

  syslog (LOG_DEBUG, "Has %d bytes from %s on socket %d\n",
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

  syslog (LOG_DEBUG, "Got %d bytes of %d bytes from %s on socket %d\n",
	  ls->bufpos, waitfor + 4, ls->str, ls->sockfd);

  if (ls->type == SOCK_DGRAM && ls->bufpos > 0)
    return 1;
  else if (ls->bufpos > 4 && waitfor + 4 == ls->bufpos)
    return 1;

  return 0;
}

/* Process a request and store reply in same buffer. */
static void
kdc_process (struct listenspec *ls)
{
  char *p;
  ssize_t plen;

  syslog (LOG_DEBUG, "Processing %d from %s on socket %d",
	  ls->bufpos, ls->str, ls->sockfd);

  if (ls->type == SOCK_DGRAM)
    plen = process (ls->buf, ls->bufpos, &p);
  else
    plen = process (ls->buf + 4, ls->bufpos - 4, &p);

  if (plen <= 0)
    {
      syslog (LOG_ERR, "Processing request failed for %s on socket %d (%d)",
	      ls->str, ls->sockfd, plen);
      memcpy (ls->buf, fatal_krberror, fatal_krberror_len);
      ls->bufpos = fatal_krberror_len;
    }
  else
    {
      memcpy (ls->buf, p, plen);
      ls->bufpos = plen;
      free (p);
    }

  syslog (LOG_DEBUG, "Have %d bytes for %s on socket %d",
	  ls->bufpos, ls->str, ls->sockfd);
}

int quit = 0;

static void
ctrlc (int signum)
{
  quit = 1;
}

#define MAX(a,b) ((a) > (b) ? (a) : (b))

/* Main KDC logic, loop around select and call kdc_accept, kdc_read,
   kdc_extension, kdc_process and kdc_send.  This return when the
   SIGINT or SIGTERM signals are received. */
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
  syslog (LOG_DEBUG, "Starting (GNUTLS `%s')", gnutls_check_version (NULL));
#else
  syslog (LOG_DEBUG, "Starting (no TLS)");
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
		    syslog (LOG_DEBUG, "Listening on %s socket %d\n",
			    ls->str, ls->sockfd);
		  FD_SET (ls->sockfd, &readfds);
		}
	    }
	}
      while ((rc = select (maxfd, &readfds, NULL, NULL, NULL)) == 0);

      if (rc < 0)
	{
	  if (errno != EINTR)
	    syslog (LOG_ERR, "Error listening on sockets (%d): %s",
		    rc, strerror (errno));
	  continue;
	}

      for (ls = listenspec; ls; ls = ls->next)
	if (ls->sockfd > 0 && FD_ISSET (ls->sockfd, &readfds))
	  {
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

  syslog (LOG_DEBUG, "Shutting down");
}
