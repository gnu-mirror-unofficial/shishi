/* starttls.c	network I/O functions to upgrade TCP connections to TLS
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

#include "internal.h"
#include <gnutls/gnutls.h>

int
_shishi_tls_init (Shishi * handle)
{
  int rc;

  rc = gnutls_global_init ();
  if (rc != GNUTLS_E_SUCCESS)
    {
      shishi_warn (handle, "TLS initialization failed: %s",
		   gnutls_strerror (rc));
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  return SHISHI_OK;
}

int
_shishi_tls_done (Shishi * handle)
{
  /* XXX call gnutls_global_deinit here.  But what if application uses
     tls?  what if more than one shishi handle is allocated? */
  return SHISHI_OK;
}

/*
 * Alternative approach: First send KDC-REQ in clear with PA-STARTTLS
 * preauth data, and have server respond with something saying it is
 * ready to go on (what should that packet look like??), and then
 * start tls on that session.  If server doesn't support PA-STARTTLS,
 * it will simply complain.  For udp we shouldn't do anything at all.
 *
 * Simpler: Use leading reserved bit in TCP length field to mean
 * STARTTLS.  (Probably better to have it mean that a new octet is
 * present, and that a 0 in that field means STARTTLS, and all other
 * fields are reserved, for future extensions.)  Yup, see complete
 * writeup in manual.
 *
 * Also need to add code to map client certificate X.509 into pre
 * authenticated principal?
 *
 * Derive Kerberos EncKDCRepPart key from TLS PRF?  Hm.
 *
 */

int
_shishi_sendrecv_tls (Shishi * handle,
		      struct sockaddr *addr,
		      const char *indata, int inlen,
		      char **outdata, int *outlen, int timeout)
{
  char tmpbuf[BUFSIZ];		/* XXX can we do without it? */
  int i;
  int sockfd;
  int ret;
  int bytes_sent, bytes_read;
  gnutls_session session;
  const int kx_prio[] = { GNUTLS_KX_ANON_DH, 0 };
  gnutls_anon_client_credentials anoncred;

  sockfd = socket (AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    {
      shishi_error_set (handle, strerror (errno));
      return SHISHI_SOCKET_ERROR;
    }

  if (connect (sockfd, addr, sizeof (*addr)) != 0)
    {
      shishi_error_set (handle, strerror (errno));
      close (sockfd);
      return SHISHI_CONNECT_ERROR;
    }

  bytes_sent = write (sockfd, "\x70\x00\x00\x01", 4);

  bytes_read = read (sockfd, tmpbuf, 4);

  if (bytes_read != 4 || memcmp (tmpbuf, "\x70\x00\x00\x02", 4) != 0)
    return SHISHI_RECVFROM_ERROR;

  gnutls_anon_allocate_client_credentials (&anoncred);
  gnutls_init (&session, GNUTLS_CLIENT);
  gnutls_set_default_priority (session);
  gnutls_credentials_set (session, GNUTLS_CRD_ANON, anoncred);
  gnutls_kx_set_priority (session, kx_prio);

  gnutls_transport_set_ptr (session, (gnutls_transport_ptr) sockfd);

  ret = gnutls_handshake (session);
  if (ret < 0)
    {
      shishi_error_printf (handle, "TLS handshake failed: %s",
			   gnutls_strerror (ret));
      return SHISHI_RECVFROM_ERROR;
    }

  shishi_error_printf (handle, "TLS handshake completed");

  gnutls_record_send (session, indata, inlen);

  ret = gnutls_record_recv (session, tmpbuf, sizeof (tmpbuf));
  if (ret == 0)
    {
      shishi_error_printf (handle, "Peer has closed the TLS connection");
      return SHISHI_RECVFROM_ERROR;
    }
  else if (ret < 0)
    {
      shishi_error_printf (handle, "TLS Error: %s", gnutls_strerror (ret));
      return SHISHI_RECVFROM_ERROR;
    }

  gnutls_bye (session, GNUTLS_SHUT_RDWR);

  if (shutdown (sockfd, SHUT_RDWR) != 0)
    {
      shishi_error_set (handle, strerror (errno));
      return SHISHI_CLOSE_ERROR;
    }

  if (close (sockfd) != 0)
    {
      shishi_error_set (handle, strerror (errno));
      return SHISHI_CLOSE_ERROR;
    }

  gnutls_deinit (session);
  gnutls_anon_free_client_credentials (anoncred);

  *outlen = ret;
  *outdata = xmalloc (*outlen);
  memcpy (*outdata, tmpbuf, *outlen);

  return SHISHI_OK;
}
