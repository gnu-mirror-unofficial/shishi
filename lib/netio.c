/* netio.c	network I/O functions
 * Copyright (C) 2002  Simon Josefsson
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

int
shishi_sendrecv_udp (Shishi * handle,
		     struct sockaddr *addr,
		     char *indata,
		     int inlen, char *outdata, int *outlen, int timeout)
{
  struct sockaddr lsa;
  struct hostent *he;
  struct sockaddr_in *lsa_inp = (struct sockaddr_in *) &lsa;
  struct protoent *proto;
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
      shishi_error_set(handle, strerror(errno));
      return SHISHI_SOCKET_ERROR;
    }

  if (bind (sockfd, (struct sockaddr *) &lsa, sizeof (lsa)) != 0)
    {
      shishi_error_set(handle, strerror(errno));
      close (sockfd);
      return SHISHI_BIND_ERROR;
    }

  bytes_sent = sendto (sockfd, (void *) indata, inlen,
		       0, addr, sizeof (*addr));
  if (bytes_sent != inlen)
    {
      shishi_error_set(handle, strerror(errno));
      return SHISHI_SENDTO_ERROR;
    }

  FD_ZERO (&readfds);
  FD_SET (sockfd, &readfds);
  tout.tv_sec = timeout;
  tout.tv_usec = 0;
  if ((rc = select (sockfd + 1, &readfds, NULL, NULL, &tout)) != 1)
    {
      if (rc == -1)
	shishi_error_set(handle, strerror(errno));
      else
	shishi_error_clear(handle);
      return SHISHI_KDC_TIMEOUT;
    }

  *outlen = recvfrom (sockfd, outdata, *outlen, 0,
		      (struct sockaddr *) &from_sa, &length);

  if (*outlen == -1)
    {
      shishi_error_set(handle, strerror(errno));
      return SHISHI_RECVFROM_ERROR;
    }

  if (close (sockfd) != 0)
    {
      shishi_error_set(handle, strerror(errno));
      return SHISHI_CLOSE_ERROR;
    }

  return SHISHI_OK;
}

int
shishi_kdc_sendrecv (Shishi * handle,
		     char *realm,
		     char *indata, int inlen, char *outdata, int *outlen)
{
  int i, j, k;
  int rc;

  for (i = 0; i < handle->nrealminfos; i++)
    if (realm && strcmp (handle->realminfos[i].name, realm) == 0)
      {
	for (j = 0; j < handle->kdcretries; j++)
	  for (k = 0; k < handle->realminfos[i].nkdcaddresses; k++)
	    {
	      struct Shishi_kdcinfo *ki =
		&handle->realminfos[i].kdcaddresses[k];

	      if (VERBOSE(handle))
		{
		  printf ("Sending to %s (%s)...\n", ki->name,
			  inet_ntoa (((struct sockaddr_in *)
				      &ki->sockaddress)->sin_addr));
		}

	      rc = shishi_sendrecv_udp (handle, &ki->sockaddress,
					indata, inlen, outdata, outlen,
					handle->kdctimeout);
	      if (rc != SHISHI_KDC_TIMEOUT)
		return rc;
	    }

	shishi_error_clear(handle);
	return SHISHI_KDC_TIMEOUT;
      }

  shishi_error_printf (handle, "No KDC defined for realm %s\n", realm);
  return SHISHI_KDC_NOT_KNOWN_FOR_REALM;
}
