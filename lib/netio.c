/* netio.c --- Network I/O functions.
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

/* Get _shishi_sendrecv_tls, etc. */
#include "starttls.h"

/* Get _shishi_realminfo, etc. */
#include "diskio.h"

/* Get _shishi_realminfo. */
#include "cfg.h"

static int
shishi_sendrecv_udp (Shishi * handle,
		     struct sockaddr *addr,
		     const char *indata, int inlen,
		     char **outdata, size_t * outlen, size_t timeout)
{
  struct sockaddr lsa;
  struct sockaddr_in *lsa_inp = (struct sockaddr_in *) &lsa;
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
  slen = recvfrom (sockfd, tmpbuf, *outlen, 0,
		   (struct sockaddr *) &from_sa, &length);

  if (slen == -1)
    {
      shishi_error_set (handle, strerror (errno));
      return SHISHI_RECVFROM_ERROR;
    }

  *outdata = xmalloc (*outlen);
  *outlen = slen;
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
		     char **outdata, size_t * outlen, size_t timeout)
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

  *outdata = xmalloc (*outlen);
  *outlen = slen;
  memcpy (*outdata, tmpbuf, *outlen);

  if (close (sockfd) != 0)
    {
      shishi_error_set (handle, strerror (errno));
      return SHISHI_CLOSE_ERROR;
    }

  return SHISHI_OK;
}

static int
shishi_kdc_sendrecv_1 (Shishi * handle, struct Shishi_kdcinfo *ki,
		       const char *indata, size_t inlen,
		       char **outdata, size_t * outlen,
		       Shishi_tkts_hint * hint)
{
  const char *protname;
  int rc;

  switch (ki->protocol)
    {
#ifdef USE_STARTTLS
    case TLS:
      protname = "tls";
      break;
#endif

    case TCP:
      protname = "tcp";
      break;

    default:
    case UDP:
      protname = "udp";
      break;
    }

  shishi_verbose (handle, "Sending to %s (%s) via %s", ki->name,
		  inet_ntoa (((struct sockaddr_in *)
			      &ki->sockaddress)->sin_addr),
		  protname);

  switch (ki->protocol)
    {
#ifdef USE_STARTTLS
    case TLS:
      rc = _shishi_sendrecv_tls (handle, &ki->sockaddress,
				 indata, inlen, outdata, outlen,
				 handle->kdctimeout, hint);
      break;
#endif

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
			    char **outdata, size_t * outlen,
			    Shishi_tkts_hint * hint)
{
  struct Shishi_realminfo *ri;
  size_t j, k;
  int rc;

  ri = _shishi_realminfo (handle, realm);
  if (!ri)
    {
      shishi_error_printf (handle, "No KDC defined for realm %s", realm);
      return SHISHI_KDC_NOT_KNOWN_FOR_REALM;
    }

  for (j = 0; j < handle->kdcretries; j++)
    for (k = 0; k < ri->nkdcaddresses; k++)
      {
	rc = shishi_kdc_sendrecv_1 (handle, &ri->kdcaddresses[k],
				    indata, inlen, outdata, outlen, hint);
	if (rc != SHISHI_KDC_TIMEOUT)
	  return rc;
      }

  shishi_error_clear (handle);
  return SHISHI_KDC_TIMEOUT;
}

static int
shishi_kdc_sendrecv_srv_1 (Shishi * handle, char *realm,
			   const char *indata, size_t inlen,
			   char **outdata, size_t * outlen, Shishi_dns rrs)
{
  int rc;

  for (; rrs; rrs = rrs->next)
    {
      Shishi_dns_srv srv = rrs->rr;
      struct addrinfo hints;
      struct addrinfo *ai;
      char *port;

      if (rrs->class != SHISHI_DNS_IN)
	continue;
      if (rrs->type != SHISHI_DNS_SRV)
	continue;

      shishi_verbose (handle, "Located SRV RRs server %s:%d",
		      srv->name, srv->port);

      memset (&hints, 0, sizeof (hints));
      hints.ai_socktype = SOCK_DGRAM;
      port = xasprintf ("%d", srv->port);
      rc = getaddrinfo (srv->name, port, &hints, &ai);
      free (port);

      if (rc != 0)
	{
	  shishi_warn (handle, "Unknown KDC host `%s' (gai rc %d)",
		       srv->name, rc);
	  continue;
	}

      shishi_verbose (handle, "Sending to %s:%d (%s)",
		      srv->name, srv->port,
		      inet_ntoa (((struct sockaddr_in *)
				  ai->ai_addr)->sin_addr));

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
  Shishi_dns rrs;
  char *tmp;
  int rc;

  shishi_verbose (handle, "Finding SRV RRs for %s", realm);

  tmp = xasprintf ("_kerberos._udp.%s", realm);
  rrs = shishi_resolv (tmp, SHISHI_DNS_SRV);
  free (tmp);

  if (rrs)
    rc = shishi_kdc_sendrecv_srv_1 (handle, realm, indata, inlen,
				    outdata, outlen, rrs);
  else
    {
      shishi_error_printf (handle, "No KDC SRV RRs for realm %s", realm);
      rc = SHISHI_KDC_NOT_KNOWN_FOR_REALM;
    }

  shishi_resolv_free (rrs);

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

  shishi_verbose (handle, "Trying direct realm host mapping for %s", realm);

  se = getservbyname ("kerberos", NULL);
  if (se)
    port = xasprintf ("%d", ntohs (se->s_port));
  else
    port = xasprintf ("%d", 88);

  memset (&hints, 0, sizeof (hints));
  hints.ai_socktype = SOCK_DGRAM;
  rc = getaddrinfo (realm, port, &hints, &ai);

  if (rc != 0)
    {
      shishi_error_printf (handle, "No direct realm host for realm %s",
			   realm);
      free (port);
      return SHISHI_KDC_NOT_KNOWN_FOR_REALM;
    }

  shishi_verbose (handle, "Sending to %s:%s (%s)", realm, port,
		  inet_ntoa (((struct sockaddr_in *) ai->ai_addr)->sin_addr));

  free (port);

  rc = shishi_sendrecv_udp (handle, ai->ai_addr,
			    indata, inlen, outdata, outlen,
			    handle->kdctimeout);

  freeaddrinfo (ai);

  return rc;
}

int
shishi_kdc_sendrecv_hint (Shishi * handle, char *realm,
			  const char *indata, size_t inlen,
			  char **outdata, size_t * outlen,
			  Shishi_tkts_hint * hint)
{
  int rc;

  rc = shishi_kdc_sendrecv_static (handle, realm, indata, inlen,
				   outdata, outlen, hint);
  if (rc == SHISHI_KDC_TIMEOUT || rc == SHISHI_KDC_NOT_KNOWN_FOR_REALM)
    rc = shishi_kdc_sendrecv_srv (handle, realm,
				  indata, inlen, outdata, outlen);
  if (rc == SHISHI_KDC_TIMEOUT || rc == SHISHI_KDC_NOT_KNOWN_FOR_REALM)
    rc = shishi_kdc_sendrecv_direct (handle, realm,
				     indata, inlen, outdata, outlen);

  return rc;
}

int
shishi_kdc_sendrecv (Shishi * handle, char *realm,
		     const char *indata, size_t inlen,
		     char **outdata, size_t * outlen)
{
  return shishi_kdc_sendrecv_hint (handle, realm, indata, inlen,
				   outdata, outlen, NULL);
}
