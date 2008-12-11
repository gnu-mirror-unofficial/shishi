/* starttls.c --- Network I/O functions for Shishi over TLS.
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

#include "internal.h"
#include <gnutls/gnutls.h>
#include "starttls.h"

/* Initialize TLS subsystem. Typically invoked by shishi_init. */
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

/* Deinitialize TLS subsystem.  Typically invoked by shishi_done. */
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
 * Derive EncKDCRepPart key from TLS PRF?  Hm.
 *
 * The code currently implements
 * draft-josefsson-krb-tcp-expansion-02.txt and
 * draft-josefsson-kerberos5-starttls-02.txt.
 */

#define STARTTLS_CLIENT_REQUEST "\x70\x00\x00\x01"
#define STARTTLS_SERVER_ACCEPT "\x00\x00\x00\x00"
#define STARTTLS_LEN 4

#define C2I(buf) ((buf[3] & 0xFF) |		\
		  ((buf[2] & 0xFF) << 8) |	\
		  ((buf[1] & 0xFF) << 16) |	\
		  ((buf[0] & 0xFF) << 24))

/* Negotiate TLS and send and receive packets on an open socket. */
static int
_shishi_sendrecv_tls1 (Shishi * handle,
		       int sockfd,
		       gnutls_session session,
		       const char *indata, size_t inlen,
		       char **outdata, size_t * outlen, size_t timeout)
{
  int ret;
  ssize_t bytes_sent, bytes_read;
  char extbuf[STARTTLS_LEN + 1];
  static size_t session_data_size = 0;
  static void *session_data = NULL;
  char tmpbuf[4];
  unsigned int status;

  bytes_sent = write (sockfd, STARTTLS_CLIENT_REQUEST, STARTTLS_LEN);
  if (bytes_sent != STARTTLS_LEN)
    return SHISHI_SENDTO_ERROR;

  bytes_read = read (sockfd, extbuf, sizeof (extbuf));
  if (bytes_read != STARTTLS_LEN ||
      memcmp (extbuf, STARTTLS_SERVER_ACCEPT, STARTTLS_LEN) != 0)
    return SHISHI_RECVFROM_ERROR;

  gnutls_transport_set_ptr (session, (gnutls_transport_ptr) sockfd);

  if (session_data_size > 0)
    gnutls_session_set_data (session, session_data, session_data_size);

  ret = gnutls_handshake (session);
  if (ret < 0)
    {
      shishi_error_printf (handle, "TLS handshake failed (%d): %s",
			   ret, gnutls_strerror (ret));
      return SHISHI_RECVFROM_ERROR;
    }

  if (gnutls_session_is_resumed (session) != 0)
    shishi_error_printf (handle, "TLS handshake completed (resumed)");
  else
    shishi_error_printf (handle, "TLS handshake completed (not resumed)");

  ret = gnutls_certificate_verify_peers2 (session, &status);
  if (ret != 0 || status != 0)
    {
      shishi_error_printf (handle, "TLS verification of CA failed (%d/%d)",
			   ret, status);
      return SHISHI_RECVFROM_ERROR;
    }

  /* XXX: We need to verify the CA cert further here. */

  if (session_data_size == 0)
    {
      ret = gnutls_session_get_data (session, NULL, &session_data_size);
      if (ret < 0)
	{
	  shishi_error_printf (handle, "TLS gsgd(1) failed (%d): %s",
			       ret, gnutls_strerror (ret));
	  return SHISHI_RECVFROM_ERROR;
	}
      session_data = xmalloc (session_data_size);
      ret = gnutls_session_get_data (session, session_data,
				     &session_data_size);
      if (ret < 0)
	{
	  shishi_error_printf (handle, "TLS gsgd(2) failed (%d): %s",
			       ret, gnutls_strerror (ret));
	  return SHISHI_RECVFROM_ERROR;
	}
    }

  tmpbuf[3] = inlen & 0xFF;
  tmpbuf[2] = (inlen >> 8) & 0xFF;
  tmpbuf[1] = (inlen >> 16) & 0xFF;
  tmpbuf[0] = (inlen >> 24) & 0xFF;

  bytes_sent = gnutls_record_send (session, tmpbuf, 4);
  if (bytes_sent != 4)
    {
      shishi_error_printf (handle, "Bad TLS write (%d < 4)",
			   bytes_sent);
      return SHISHI_SENDTO_ERROR;
    }

  bytes_sent = gnutls_record_send (session, indata, inlen);
  if (bytes_sent != (ssize_t) inlen)
    {
      shishi_error_printf (handle, "Bad TLS write (%d < %d)",
			   bytes_sent, inlen);
      return SHISHI_SENDTO_ERROR;
    }

  bytes_read = gnutls_record_recv (session, tmpbuf, 4);
  if (bytes_read != 4)
    {
      shishi_error_printf (handle, "Bad TLS read (%d < 4)",
			   bytes_read);
      return SHISHI_SENDTO_ERROR;
    }

  /* XXX sanities input. */
  *outlen = C2I(tmpbuf);
  *outdata = xmalloc (*outlen);

  bytes_read = gnutls_record_recv (session, *outdata, *outlen);
  if (bytes_read == 0)
    {
      shishi_error_printf (handle, "Peer has closed the TLS connection");
      free (*outdata);
      return SHISHI_RECVFROM_ERROR;
    }
  else if (bytes_read < 0)
    {
      shishi_error_printf (handle, "TLS Error (%d): %s",
			   ret, gnutls_strerror (ret));
      free (*outdata);
      return SHISHI_RECVFROM_ERROR;
    }
  else if (bytes_read != (ssize_t) *outlen)
    {
      shishi_error_printf (handle, "TLS Read error (%d != %d)",
			   *outlen, bytes_read);
      free (*outdata);
      return SHISHI_RECVFROM_ERROR;
    }

  do
    ret = gnutls_bye (session, GNUTLS_SHUT_RDWR);
  while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);

  if (ret != GNUTLS_E_SUCCESS)
    shishi_error_printf (handle, "TLS Disconnected failed (%d): %s",
			 ret, gnutls_strerror (ret));

  return SHISHI_OK;
}

/* Send request to KDC over TLS, receive reply, and disconnect. */
int
_shishi_sendrecv_tls (Shishi * handle,
		      struct sockaddr *addr,
		      const char *indata, size_t inlen,
		      char **outdata, size_t * outlen,
		      size_t timeout, Shishi_tkts_hint * hint)
{
  const int kx_prio[] = { GNUTLS_KX_RSA, GNUTLS_KX_DHE_DSS,
    GNUTLS_KX_DHE_RSA, GNUTLS_KX_ANON_DH, 0
  };
  gnutls_session session;
  gnutls_anon_client_credentials anoncred;
  gnutls_certificate_credentials x509cred;
  int sockfd;
  int ret, outerr;
  const char *cafile = shishi_x509ca_default_file (handle);
  const char *certfile = shishi_x509cert_default_file (handle);
  const char *keyfile = shishi_x509key_default_file (handle);

  ret = gnutls_init (&session, GNUTLS_CLIENT);
  if (ret != GNUTLS_E_SUCCESS)
    {
      shishi_error_printf (handle, "TLS init failed (%d): %s",
			   ret, gnutls_strerror (ret));
      return SHISHI_CRYPTO_ERROR;
    }

  ret = gnutls_set_default_priority (session);
  if (ret != GNUTLS_E_SUCCESS)
    {
      shishi_error_printf (handle, "TLS sdp failed (%d): %s",
			   ret, gnutls_strerror (ret));
      return SHISHI_CRYPTO_ERROR;
    }

  ret = gnutls_anon_allocate_client_credentials (&anoncred);
  if (ret != GNUTLS_E_SUCCESS)
    {
      shishi_error_printf (handle, "TLS aacs failed (%d): %s",
			   ret, gnutls_strerror (ret));
      return SHISHI_CRYPTO_ERROR;
    }

  ret = gnutls_credentials_set (session, GNUTLS_CRD_ANON, anoncred);
  if (ret != GNUTLS_E_SUCCESS)
    {
      shishi_error_printf (handle, "TLS cs failed (%d): %s",
			   ret, gnutls_strerror (ret));
      return SHISHI_CRYPTO_ERROR;
    }

  ret = gnutls_certificate_allocate_credentials (&x509cred);
  if (ret != GNUTLS_E_SUCCESS)
    {
      shishi_error_printf (handle, "TLS cac failed (%d): %s",
			   ret, gnutls_strerror (ret));
      return SHISHI_CRYPTO_ERROR;
    }

  ret = gnutls_certificate_set_x509_trust_file (x509cred, cafile,
						GNUTLS_X509_FMT_PEM);
  if (ret != GNUTLS_E_SUCCESS && ret != GNUTLS_E_FILE_ERROR)
    {
      shishi_error_printf (handle, "TLS csxtf failed (%d): %s",
			   ret, gnutls_strerror (ret));
      return SHISHI_CRYPTO_ERROR;
    }
  else if (ret == GNUTLS_E_SUCCESS)
    shishi_error_printf (handle, "Loaded CA certificate");

  ret = gnutls_certificate_set_x509_key_file (x509cred, certfile,
					      keyfile, GNUTLS_X509_FMT_PEM);
  if (ret != GNUTLS_E_SUCCESS && ret != GNUTLS_E_FILE_ERROR)
    {
      shishi_error_printf (handle, "TLS csxkf failed (%d): %s",
			   ret, gnutls_strerror (ret));
      return SHISHI_CRYPTO_ERROR;
    }
  else if (ret == GNUTLS_E_SUCCESS)
    shishi_error_printf (handle, "Loaded client certificate");

  ret = gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509cred);
  if (ret != GNUTLS_E_SUCCESS)
    {
      shishi_error_printf (handle, "TLS cs X.509 failed (%d): %s",
			   ret, gnutls_strerror (ret));
      return SHISHI_CRYPTO_ERROR;
    }

  ret = gnutls_kx_set_priority (session, kx_prio);
  if (ret != GNUTLS_E_SUCCESS)
    {
      shishi_error_printf (handle, "TLS ksp failed (%d): %s",
			   ret, gnutls_strerror (ret));
      return SHISHI_CRYPTO_ERROR;
    }

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

  /* Core part. */
  outerr = _shishi_sendrecv_tls1 (handle, sockfd, session, indata, inlen,
				  outdata, outlen, timeout);

  ret = shutdown (sockfd, SHUT_RDWR);
  if (ret != 0)
    {
      shishi_error_printf (handle, "Shutdown failed (%d): %s",
			   ret, strerror (errno));
      if (outerr == SHISHI_OK)
	outerr = SHISHI_CLOSE_ERROR;
    }

  ret = close (sockfd);
  if (ret != 0)
    {
      shishi_error_printf (handle, "Close failed (%d): %s",
			   ret, strerror (errno));
      if (outerr == SHISHI_OK)
	outerr = SHISHI_CLOSE_ERROR;
    }

  gnutls_deinit (session);
  gnutls_anon_free_client_credentials (anoncred);

  return outerr;
}
