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

/* Get Shishid stuff. */
#include "kdc.h"

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
	syslog (LOG_INFO, "Closing %s...\n", ls->str);
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
	syslog (LOG_INFO, "Trying to upgrade to TLS...");

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
      plen = process (ls->buf, ls->bufpos, &p);
      printf ("TLS process %d sending %d\n", ls->bufpos, plen);
    }
  else
#endif
    {
      if (ls->type == SOCK_STREAM)
	plen = process (ls->buf + 4, ls->bufpos - 4, &p);
      else
	plen = process (ls->buf, ls->bufpos, &p);
    }

  printf ("Process yielded %d bytes\n", plen);

  if (plen <= 0)
    {
      memcpy (ls->buf, fatal_krberror, fatal_krberror_len);
      ls->bufpos = fatal_krberror_len;
    }
  else
    {
      memcpy (ls->buf, p, plen);
      ls->bufpos = plen;
      free (p);
    }
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
	    syslog (LOG_ERR, "Error listening on sockets (%d): %s",
		    rc, strerror (errno));
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
