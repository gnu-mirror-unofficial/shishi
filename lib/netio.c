/* netio.c	network I/O functions
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

static int
shishi_sendrecv_udp (Shishi * handle,
		     struct sockaddr *addr,
		     const char *indata, int inlen,
		     char **outdata, int *outlen, int timeout)
{
  struct sockaddr lsa;
  struct sockaddr_in *lsa_inp = (struct sockaddr_in *) &lsa;
  char tmpbuf[BUFSIZ];		/* XXX can we do without it?
				   MSG_PEEK|MSG_TRUNC doesn't work for udp.. */
  int sockfd;
  int bytes_sent;
  struct sockaddr_storage from_sa;
  int length = sizeof (struct sockaddr_storage);
  fd_set readfds;
  struct timeval tout;
  int rc;

  memset (&lsa, 0, sizeof (lsa));
  lsa_inp->sin_family = AF_INET;
  lsa_inp->sin_addr.s_addr = htonl (INADDR_ANY);

  sockfd = socket (AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0)
    {
      shishi_error_set (handle, strerror (errno));
      return SHISHI_SOCKET_ERROR;
    }

  if (bind (sockfd, (struct sockaddr *) &lsa, sizeof (lsa)) != 0)
    {
      shishi_error_set (handle, strerror (errno));
      close (sockfd);
      return SHISHI_BIND_ERROR;
    }

  bytes_sent = sendto (sockfd, (const void *) indata, inlen,
		       0, addr, sizeof (*addr));
  if (bytes_sent != inlen)
    {
      shishi_error_set (handle, strerror (errno));
      return SHISHI_SENDTO_ERROR;
    }

  FD_ZERO (&readfds);
  FD_SET (sockfd, &readfds);
  tout.tv_sec = timeout;
  tout.tv_usec = 0;
  if ((rc = select (sockfd + 1, &readfds, NULL, NULL, &tout)) != 1)
    {
      if (rc == -1)
	shishi_error_set (handle, strerror (errno));
      else
	shishi_error_clear (handle);
      return SHISHI_KDC_TIMEOUT;
    }

  *outlen = sizeof (tmpbuf);
  *outlen = recvfrom (sockfd, tmpbuf, *outlen, 0,
		      (struct sockaddr *) &from_sa, &length);

  if (*outlen == -1)
    {
      shishi_error_set (handle, strerror (errno));
      return SHISHI_RECVFROM_ERROR;
    }

  *outdata = xmalloc (*outlen);
  memcpy (*outdata, tmpbuf, *outlen);

  if (close (sockfd) != 0)
    {
      shishi_error_set (handle, strerror (errno));
      return SHISHI_CLOSE_ERROR;
    }

  return SHISHI_OK;
}

static int
shishi_sendrecv_tcp (Shishi * handle,
		     struct sockaddr *addr,
		     const char *indata, int inlen,
		     char **outdata, int *outlen, int timeout)
{
  char tmpbuf[BUFSIZ];		/* XXX can we do without it?
				   MSG_PEEK|MSG_TRUNC doesn't work for udp.. */
  int sockfd;
  int bytes_sent;
  struct sockaddr_storage from_sa;
  int length = sizeof (struct sockaddr_storage);
  fd_set readfds;
  struct timeval tout;
  int rc;

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

  tmpbuf[3] = inlen & 0xFF;
  tmpbuf[2] = (inlen >> 8) & 0xFF;
  tmpbuf[1] = (inlen >> 16) & 0xFF;
  tmpbuf[0] = (inlen >> 24) & 0xFF;

  bytes_sent = write (sockfd, tmpbuf, 4);

  bytes_sent = write (sockfd, (const void *) indata, inlen);
  if (bytes_sent != inlen)
    {
      shishi_error_set (handle, strerror (errno));
      return SHISHI_SENDTO_ERROR;
    }

  FD_ZERO (&readfds);
  FD_SET (sockfd, &readfds);
  tout.tv_sec = timeout;
  tout.tv_usec = 0;
  if ((rc = select (sockfd + 1, &readfds, NULL, NULL, &tout)) != 1)
    {
      if (rc == -1)
	shishi_error_set (handle, strerror (errno));
      else
	shishi_error_clear (handle);
      return SHISHI_KDC_TIMEOUT;
    }

  *outlen = 4;
  *outlen = recvfrom (sockfd, tmpbuf, *outlen, 0,
		      (struct sockaddr *) &from_sa, &length);
  if (*outlen == -1)
    {
      shishi_error_set (handle, strerror (errno));
      return SHISHI_RECVFROM_ERROR;
    }

  *outlen = sizeof (tmpbuf);
  *outlen = recvfrom (sockfd, tmpbuf, *outlen, 0,
		      (struct sockaddr *) &from_sa, &length);

  *outdata = xmalloc (*outlen);
  memcpy (*outdata, tmpbuf, *outlen);

  if (close (sockfd) != 0)
    {
      shishi_error_set (handle, strerror (errno));
      return SHISHI_CLOSE_ERROR;
    }

  return SHISHI_OK;
}

#ifdef USE_GNUTLS

#include <gnutls/gnutls.h>

/* XXX this is bogus, we should do a STARTTLS approach instead.

   I.e., first send KDC-REQ in clear with PA-STARTTLS preauth data,
   and if KDC doesn't reject it, start tls on that session.
   For udp we shouldn't do anything at all.

   Also need to add code to map client certificate X.509 into
   pre authenticated principal.

   Derive Kerberos EncKDCRepPart key from TLS PRF?  Hm.

   Simpler: Use leading reserved bit in TCP length field to mean
   STARTTLS.  (Probably better to have it mean that a new octet is
   present, and that a 0 in that field means STARTTLS, and all other
   fields are reserved, for future extensions.)
*/

static int
shishi_sendrecv_tls (Shishi * handle,
		     struct sockaddr *addr,
		     const char *indata, int inlen,
		     char **outdata, int *outlen, int timeout)
{
  char tmpbuf[BUFSIZ];		/* XXX can we do without it?
				   MSG_PEEK|MSG_TRUNC doesn't work for udp.. */
  int i;
  int sockfd;
  int ret;
  gnutls_session session;
  gnutls_certificate_credentials xcred;
  /* Allow connections to servers that have OpenPGP keys as well.
   */
  const int cert_type_priority[3] = { GNUTLS_CRT_X509,
				      GNUTLS_CRT_OPENPGP, 0 };

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

   gnutls_global_init();

   /* X509 stuff */
   gnutls_certificate_allocate_credentials(&xcred);

   /* set's the trusted cas file
    */
   //gnutls_certificate_set_x509_trust_file(xcred, CAFILE, GNUTLS_X509_FMT_PEM);
   /* Initialize TLS session 
    */
   gnutls_init(&session, GNUTLS_CLIENT);

   /* Use default priorities */
   gnutls_set_default_priority(session);
   gnutls_certificate_type_set_priority(session, cert_type_priority);

   /* put the x509 credentials to the current session
    */
   gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

   gnutls_transport_set_ptr( session, (gnutls_transport_ptr)sockfd);

   /* Perform the TLS handshake
    */
   ret = gnutls_handshake( session);

   if (ret < 0) {
      fprintf(stderr, "*** Handshake failed\n");
      gnutls_perror(ret);
   } else {
      printf("- Handshake was completed\n");
   }

   tmpbuf[3] = inlen & 0xFF;
   tmpbuf[2] = (inlen >> 8) & 0xFF;
   tmpbuf[1] = (inlen >> 16) & 0xFF;
   tmpbuf[0] = (inlen >> 24) & 0xFF;

   gnutls_record_send( session, tmpbuf, 4);

   gnutls_record_send( session, indata, inlen);

   ret = gnutls_record_recv( session, tmpbuf, sizeof(tmpbuf));
   if (ret == 0) {
      printf("- Peer has closed the TLS connection\n");
   } else if (ret < 0) {
      fprintf(stderr, "*** Error: %s\n", gnutls_strerror(ret));
   } else if (ret > 0) {
      printf("- Received %d bytes: ", ret);
      for (i = 0; i < ret; i++) {
	fputc(tmpbuf[i], stdout);
      }
      fputs("\n", stdout);
   }
   gnutls_bye( session, GNUTLS_SHUT_RDWR);

   shutdown(sockfd, SHUT_RDWR);     /* no more receptions */

   if (close (sockfd) != 0)
     {
       shishi_error_set (handle, strerror (errno));
       return SHISHI_CLOSE_ERROR;
     }

   gnutls_deinit(session);

   gnutls_certificate_free_credentials(xcred);

   gnutls_global_deinit();

   *outlen = ret - 4;
   *outdata = xmalloc (*outlen);
   memcpy (*outdata, tmpbuf + 4, *outlen);

  return SHISHI_OK;
}

#else

static int
shishi_sendrecv_tls (Shishi * handle,
		     struct sockaddr *addr,
		     const char *indata, int inlen,
		     char **outdata, int *outlen, int timeout)
{
  return !SHISHI_OK;
}

#endif

static int
shishi_kdc_sendrecv_1 (Shishi * handle, struct Shishi_kdcinfo *ki,
		       const char *indata, size_t inlen,
		       char **outdata, size_t * outlen)
{
  int rc;

  if (VERBOSE (handle))
    printf ("Sending to %s (%s) via %s...\n", ki->name,
	    inet_ntoa (((struct sockaddr_in *) &ki->sockaddress)->sin_addr),
	    ki->protocol == TCP ? "tcp" : ki->protocol == TLS ? "tls" : "udp");

  switch (ki->protocol)
    {
    case TLS:
      rc = shishi_sendrecv_tls (handle, &ki->sockaddress,
				indata, inlen, outdata, outlen,
				handle->kdctimeout);
      break;

    case TCP:
      rc = shishi_sendrecv_tcp (handle, &ki->sockaddress,
				indata, inlen, outdata, outlen,
				handle->kdctimeout);
      break;

    case UDP:
    default:
      rc = shishi_sendrecv_udp (handle, &ki->sockaddress,
				indata, inlen, outdata, outlen,
				handle->kdctimeout);
      break;
    }

  return rc;
}

static int
shishi_kdc_sendrecv_static (Shishi * handle, char *realm,
			    const char *indata, size_t inlen,
			    char **outdata, size_t * outlen)
{
  struct Shishi_realminfo *ri;
  size_t j, k;
  int rc;

  ri = shishi_realminfo (handle, realm);
  if (!ri)
    {
      shishi_error_printf (handle, "No KDC defined for realm %s", realm);
      return SHISHI_KDC_NOT_KNOWN_FOR_REALM;
    }

  for (j = 0; j < handle->kdcretries; j++)
    for (k = 0; k < ri->nkdcaddresses; k++)
      {
	rc = shishi_kdc_sendrecv_1 (handle, &ri->kdcaddresses[k],
				    indata, inlen, outdata, outlen);
	if (rc != SHISHI_KDC_TIMEOUT)
	  return rc;
      }

  shishi_error_clear (handle);
  return SHISHI_KDC_TIMEOUT;
}

static int
shishi_kdc_sendrecv_srv_1 (Shishi * handle, char *realm,
			   const char *indata, size_t inlen,
			   char **outdata, size_t * outlen, dnshost_t rrs)
{
  int rc;

  for (; rrs; rrs = rrs->next)
    {
      dns_srv_t srv = (dns_srv_t) rrs->rr;
      struct addrinfo hints;
      struct addrinfo *ai;
      char *port;

      if (rrs->class != C_IN)
	continue;
      if (rrs->type != T_SRV)
	continue;

      if (VERBOSE (handle))
	printf ("Located SRV RRs server %s:%d...\n", srv->name, srv->port);

      memset (&hints, 0, sizeof (hints));
      hints.ai_socktype = SOCK_DGRAM;
      asprintf (&port, "%d", srv->port);
      rc = getaddrinfo (srv->name, port, &hints, &ai);
      free (port);

      if (rc != 0)
	{
	  shishi_warn (handle, "Unknown KDC host `%s' (gai rc %d)",
		       srv->name, rc);
	  continue;
	}

      if (VERBOSE (handle))
	printf ("Sending to %s:%d (%s)...\n", srv->name, srv->port,
		inet_ntoa (((struct sockaddr_in *) ai->ai_addr)->sin_addr));

      rc = shishi_sendrecv_udp (handle, ai->ai_addr,
				indata, inlen, outdata, outlen,
				handle->kdctimeout);

      freeaddrinfo (ai);

      if (rc != SHISHI_KDC_TIMEOUT)
	return rc;
    }

  return SHISHI_KDC_TIMEOUT;
}

static int
shishi_kdc_sendrecv_srv (Shishi * handle, char *realm,
			 const char *indata, size_t inlen,
			 char **outdata, size_t * outlen)
{
  dnshost_t rrs;
  char *tmp;
  int rc;

  if (VERBOSE (handle))
    printf ("Finding SRV RRs for %s...\n", realm);

  asprintf (&tmp, "_kerberos._udp.%s", realm);
  rrs = _shishi_resolv (tmp, T_SRV);
  free (tmp);

  if (rrs)
    rc = shishi_kdc_sendrecv_srv_1 (handle, realm, indata, inlen,
				    outdata, outlen, rrs);
  else
    {
      shishi_error_printf (handle, "No KDC SRV RRs for realm %s", realm);
      rc = SHISHI_KDC_NOT_KNOWN_FOR_REALM;
    }

  _shishi_resolv_free (rrs);

  return rc;
}

static int
shishi_kdc_sendrecv_direct (Shishi * handle, char *realm,
			    const char *indata, size_t inlen,
			    char **outdata, size_t * outlen)
{
  struct servent *se;
  struct addrinfo hints;
  struct addrinfo *ai;
  char *port;
  int rc;

  if (VERBOSE (handle))
    printf ("Trying direct realm host mapping for %s...\n", realm);

  se = getservbyname ("kerberos", NULL);
  if (se)
    asprintf (&port, "%d", ntohs (se->s_port));
  else
    asprintf (&port, "%d", 88);

  memset (&hints, 0, sizeof (hints));
  hints.ai_socktype = SOCK_DGRAM;
  rc = getaddrinfo (realm, port, &hints, &ai);

  free (port);

  if (rc != 0)
    {
      shishi_error_printf (handle, "No direct realm host for realm %s",
			   realm);
      return SHISHI_KDC_NOT_KNOWN_FOR_REALM;
    }

  if (VERBOSE (handle))
    printf ("Sending to %s:%s (%s)...\n", realm, port,
	    inet_ntoa (((struct sockaddr_in *) ai->ai_addr)->sin_addr));

  rc = shishi_sendrecv_udp (handle, ai->ai_addr,
			    indata, inlen, outdata, outlen,
			    handle->kdctimeout);

  freeaddrinfo (ai);

  return rc;
}

int
shishi_kdc_sendrecv (Shishi * handle, char *realm,
		     const char *indata, size_t inlen,
		     char **outdata, size_t * outlen)
{
  int rc;

  rc = shishi_kdc_sendrecv_static (handle, realm,
				   indata, inlen, outdata, outlen);

  if (rc == SHISHI_KDC_TIMEOUT || rc == SHISHI_KDC_NOT_KNOWN_FOR_REALM)
    rc = shishi_kdc_sendrecv_srv (handle, realm,
				  indata, inlen, outdata, outlen);
  if (rc == SHISHI_KDC_TIMEOUT || rc == SHISHI_KDC_NOT_KNOWN_FOR_REALM)
    rc = shishi_kdc_sendrecv_direct (handle, realm,
				     indata, inlen, outdata, outlen);

  return rc;
}
