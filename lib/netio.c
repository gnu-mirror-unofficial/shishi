/* netio.c --- Network I/O functions.
 * Copyright (C) 2002-2013 Simon Josefsson
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

/* Get _shishi_sendrecv_tls, etc. */
#include "starttls.h"

/* Get _shishi_realminfo, etc. */
#include "diskio.h"

/* Get _shishi_realminfo. */
#include "cfg.h"

static int
sendrecv_udp (Shishi * handle,
	      struct addrinfo *ai,
	      const char *indata, int inlen, char **outdata, size_t * outlen)
{
  char tmpbuf[BUFSIZ];		/* XXX can we do without it?
				   MSG_PEEK|MSG_TRUNC doesn't work for udp.. */
  int sockfd;
  int bytes_sent;
  fd_set readfds;
  struct timeval tout;
  ssize_t slen;
  int rc;

  sockfd = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (sockfd < 0)
    {
      shishi_error_set (handle, strerror (errno));
      return SHISHI_SOCKET_ERROR;
    }

  if (connect (sockfd, ai->ai_addr, ai->ai_addrlen) != 0)
    {
      shishi_error_set (handle, strerror (errno));
      close (sockfd);
      return SHISHI_BIND_ERROR;
    }

  bytes_sent = write (sockfd, indata, inlen);
  if (bytes_sent != inlen)
    {
      shishi_error_set (handle, strerror (errno));
      close (sockfd);
      return SHISHI_SENDTO_ERROR;
    }

  FD_ZERO (&readfds);
  FD_SET (sockfd, &readfds);
  tout.tv_sec = handle->kdctimeout;
  tout.tv_usec = 0;
  if ((rc = select (sockfd + 1, &readfds, NULL, NULL, &tout)) != 1)
    {
      if (rc == -1)
	shishi_error_set (handle, strerror (errno));
      else
	shishi_error_clear (handle);
      close (sockfd);
      return SHISHI_KDC_TIMEOUT;
    }

  *outlen = sizeof (tmpbuf);
  slen = read (sockfd, tmpbuf, *outlen);
  if (slen == -1)
    {
      shishi_error_set (handle, strerror (errno));
      close (sockfd);
      return SHISHI_RECVFROM_ERROR;
    }

  *outdata = xmalloc (slen);
  *outlen = slen;
  memcpy (*outdata, tmpbuf, slen);

  if (close (sockfd) != 0)
    {
      shishi_error_set (handle, strerror (errno));
      return SHISHI_CLOSE_ERROR;
    }

  return SHISHI_OK;
}

static int
sendrecv_tcp (Shishi * handle,
	      struct addrinfo *ai,
	      const char *indata, int inlen, char **outdata, size_t * outlen)
{
  char tmpbuf[BUFSIZ];		/* XXX can we do without it?
				   MSG_PEEK|MSG_TRUNC doesn't work for udp.. */
  int sockfd;
  int bytes_sent;
  struct sockaddr_storage from_sa;
  socklen_t length = sizeof (struct sockaddr_storage);
  fd_set readfds;
  struct timeval tout;
  int rc;
  ssize_t slen;

  sockfd = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (sockfd < 0)
    {
      shishi_error_set (handle, strerror (errno));
      return SHISHI_SOCKET_ERROR;
    }

  if (connect (sockfd, ai->ai_addr, ai->ai_addrlen) != 0)
    {
      shishi_error_set (handle, strerror (errno));
      close (sockfd);
      return SHISHI_BIND_ERROR;
    }

  tmpbuf[3] = inlen & 0xFF;
  tmpbuf[2] = (inlen >> 8) & 0xFF;
  tmpbuf[1] = (inlen >> 16) & 0xFF;
  tmpbuf[0] = (inlen >> 24) & 0xFF;

  bytes_sent = write (sockfd, tmpbuf, 4);
  if (bytes_sent != 4)
    {
      shishi_error_set (handle, strerror (errno));
      return SHISHI_SENDTO_ERROR;
    }

  bytes_sent = write (sockfd, (const void *) indata, inlen);
  if (bytes_sent != inlen)
    {
      shishi_error_set (handle, strerror (errno));
      return SHISHI_SENDTO_ERROR;
    }

  FD_ZERO (&readfds);
  FD_SET (sockfd, &readfds);
  tout.tv_sec = handle->kdctimeout;
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
  slen = recvfrom (sockfd, tmpbuf, *outlen, 0,
		   (struct sockaddr *) &from_sa, &length);
  if (slen == -1)
    {
      shishi_error_set (handle, strerror (errno));
      return SHISHI_RECVFROM_ERROR;
    }

  *outlen = sizeof (tmpbuf);
  slen = recvfrom (sockfd, tmpbuf, *outlen, 0,
		   (struct sockaddr *) &from_sa, &length);
  if (slen == -1)
    {
      shishi_error_set (handle, strerror (errno));
      return SHISHI_RECVFROM_ERROR;
    }

  *outdata = xmalloc (slen);
  *outlen = slen;
  memcpy (*outdata, tmpbuf, slen);

  if (close (sockfd) != 0)
    {
      shishi_error_set (handle, strerror (errno));
      return SHISHI_CLOSE_ERROR;
    }

  return SHISHI_OK;
}

static int
sendrecv_host (Shishi * handle,
	       int transport, const char *host, const char *port,
	       const char *indata, size_t inlen,
	       char **outdata, size_t * outlen)
{
  struct addrinfo hints;
  struct addrinfo *ai;
  int rc;

  memset (&hints, 0, sizeof (hints));
  if (transport == TCP || transport == TLS)
    hints.ai_socktype = SOCK_STREAM;
  else
    hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_ADDRCONFIG;

  if (port == NULL)
    port = "88";

  rc = getaddrinfo (host, port, &hints, &ai);
  if (rc != 0)
    {
      shishi_error_printf (handle, "Cannot find host %s", host);
      return SHISHI_KDC_NOT_KNOWN_FOR_REALM;
    }

  do
    {
      char nodename[NI_MAXHOST];
      size_t j = 0;

      rc = getnameinfo (ai->ai_addr, ai->ai_addrlen,
			nodename, sizeof (nodename), NULL, 0, NI_NUMERICHOST);
      shishi_verbose (handle, "Sending to %s (%s) port %s transport %s",
		      host, rc == 0 ? nodename : "unknown address", port,
		      _shishi_transport2string (transport));

      do
	{
	  if (transport == TCP)
	    rc = sendrecv_tcp (handle, ai, indata, inlen, outdata, outlen);
#ifdef USE_STARTTLS
	  else if (transport == TLS)
	    rc = _shishi_sendrecv_tls (handle, ai, indata, inlen,
				       outdata, outlen);
#endif
	  else
	    rc = sendrecv_udp (handle, ai, indata, inlen, outdata, outlen);

	  if (rc != SHISHI_OK)
	    shishi_verbose (handle, "Error sending to KDC: %s",
			    shishi_strerror (rc));
	}
      while (rc == SHISHI_KDC_TIMEOUT && ++j < handle->kdcretries);
    }
  while (rc != SHISHI_OK && (ai = ai->ai_next));

  return rc;
}

static int
sendrecv_srv3 (Shishi * handle,
	       int transport,
	       const char *realm,
	       const char *indata, size_t inlen,
	       char **outdata, size_t * outlen,
	       Shishi_dns rrs, bool * found_srv_records)
{
  int rc = SHISHI_KDC_NOT_KNOWN_FOR_REALM;

  for (; rrs; rrs = rrs->next)
    {
      Shishi_dns_srv srv = rrs->rr;
      char *port;

      if (rrs->class != SHISHI_DNS_IN)
	continue;
      if (rrs->type != SHISHI_DNS_SRV)
	continue;

      shishi_verbose (handle, "Found SRV host %s port %d",
		      srv->name, srv->port);
      *found_srv_records = true;

      port = xasprintf ("%d", srv->port);
      rc = sendrecv_host (handle, transport,
			  srv->name, port, indata, inlen, outdata, outlen);
      free (port);

      if (rc == SHISHI_OK)
	return rc;
    }

  return rc;
}

static int
sendrecv_srv2 (Shishi * handle,
	       int transport,
	       const char *realm,
	       const char *indata, size_t inlen,
	       char **outdata, size_t * outlen, bool * found_srv_records)
{
  Shishi_dns rrs;
  char *tmp;
  int rc;

  if (transport != UDP && transport != TCP)
    return SHISHI_KDC_NOT_KNOWN_FOR_REALM;

  tmp = xasprintf ("_kerberos._%s.%s", transport == UDP ? "udp" : "tcp",
		   realm);
  shishi_verbose (handle, "Looking up SRV for %s", tmp);
  rrs = shishi_resolv (tmp, SHISHI_DNS_SRV);
  free (tmp);

  if (rrs)
    rc = sendrecv_srv3 (handle, transport, realm, indata, inlen,
			outdata, outlen, rrs, found_srv_records);
  else
    rc = SHISHI_KDC_NOT_KNOWN_FOR_REALM;

  shishi_resolv_free (rrs);

  return rc;
}

static int
sendrecv_srv (Shishi * handle, const char *realm,
	      const char *indata, size_t inlen,
	      char **outdata, size_t * outlen, bool * found_srv_records)
{
  int rc = sendrecv_srv2 (handle, UDP, realm, indata, inlen,
			  outdata, outlen, found_srv_records);
  if (rc == SHISHI_OK)
    return rc;
  return sendrecv_srv2 (handle, TCP, realm, indata, inlen,
			outdata, outlen, found_srv_records);
}

static int
sendrecv_static (Shishi * handle, const char *realm,
		 const char *indata, size_t inlen,
		 char **outdata, size_t * outlen)
{
  struct Shishi_realminfo *ri;
  size_t k;
  int rc;

  ri = _shishi_realminfo (handle, realm);
  if (!ri || ri->nkdcaddresses == 0)
    {
      shishi_error_printf (handle, "No KDC configured for %s", realm);
      return SHISHI_KDC_NOT_KNOWN_FOR_REALM;
    }

  rc = SHISHI_KDC_NOT_KNOWN_FOR_REALM;
  for (k = 0; k < ri->nkdcaddresses; k++)
    {
      rc = sendrecv_host (handle,
			  ri->kdcaddresses[k].transport,
			  ri->kdcaddresses[k].hostname,
			  ri->kdcaddresses[k].port,
			  indata, inlen, outdata, outlen);
      if (rc == SHISHI_OK)
	return rc;
    }

  return rc;
}

/**
 * shishi_kdc_sendrecv_hint:
 * @handle: Shishi library handle create by shishi_init().
 * @realm: string with realm name.
 * @indata: Packet to send to KDC.
 * @inlen: Length of @indata.
 * @outdata: Newly allocated string with data returned from KDC.
 * @outlen: Length of @outdata.
 * @hint: a #Shishi_tkts_hint structure with flags.
 *
 * Send packet to KDC for realm and receive response.  The code finds
 * KDC addresses from configuration file, then by querying for SRV
 * records for the realm, and finally by using the realm name as a
 * hostname.
 *
 * Returns: %SHISHI_OK on success, %SHISHI_KDC_TIMEOUT if a timeout
 *   was reached, or other errors.
 **/
int
shishi_kdc_sendrecv_hint (Shishi * handle, const char *realm,
			  const char *indata, size_t inlen,
			  char **outdata, size_t * outlen,
			  Shishi_tkts_hint * hint)
{
  struct Shishi_realminfo *ri;
  bool found_srv_records = false;
  int rc;

  ri = _shishi_realminfo (handle, realm);
  if (ri && ri->nkdcaddresses > 0)
    /* If we have configured KDCs, never use DNS or direct method. */
    return sendrecv_static (handle, realm, indata, inlen, outdata, outlen);

  rc = sendrecv_srv (handle, realm, indata, inlen, outdata, outlen,
		     &found_srv_records);
  if (rc != SHISHI_OK && !found_srv_records)
    {
      shishi_verbose (handle, "No SRV RRs, trying realm host mapping for %s",
		      realm);
      rc = sendrecv_host (handle, UDP, realm, NULL,
			  indata, inlen, outdata, outlen);
    }

  return rc;
}

/**
 * shishi_kdc_sendrecv:
 * @handle: Shishi library handle create by shishi_init().
 * @realm: string with realm name.
 * @indata: Packet to send to KDC.
 * @inlen: Length of @indata.
 * @outdata: Newly allocated string with data returned from KDC.
 * @outlen: Length of @outdata.
 *
 * Send packet to KDC for realm and receive response.  The code finds
 * KDC addresses from configuration file, then by querying for SRV
 * records for the realm, and finally by using the realm name as a
 * hostname.
 *
 * Returns: %SHISHI_OK on success, %SHISHI_KDC_TIMEOUT if a timeout
 *   was reached, or other errors.
 **/
int
shishi_kdc_sendrecv (Shishi * handle, const char *realm,
		     const char *indata, size_t inlen,
		     char **outdata, size_t * outlen)
{
  return shishi_kdc_sendrecv_hint (handle, realm, indata, inlen,
				   outdata, outlen, NULL);
}
