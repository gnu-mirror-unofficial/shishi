/* netio.c	network I/O functions
 * Copyright (C) 2002  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with Shishi; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "internal.h"

int
shishi_sendrecv_udp (char *hostname,
		     char *indata,
		     int inlen, 
		     char *outdata, 
		     int * outlen)
{
  struct sockaddr_storage ssa, lsa;
  struct hostent* he;
  struct sockaddr_in* ssa_inp = (struct sockaddr_in*) &ssa;
  struct sockaddr_in* lsa_inp = (struct sockaddr_in*) &lsa;
  struct protoent *proto;
  int sockfd;
  int bytes_sent, bytes_received, total_received;
  struct sockaddr_storage from_sa;
  int length = sizeof(struct sockaddr_storage);
  fd_set readfds;
  struct timeval timeout = {0, 0};

  memset (&ssa, 0, sizeof(ssa));
  he = gethostbyname(hostname);
  if (he != NULL && he->h_addr_list[0] != NULL)
    {
      ssa_inp->sin_family = he->h_addrtype;
      memcpy(&ssa_inp->sin_addr, he->h_addr_list[0], he->h_length);
    }

  proto = getprotobyname ("kerberos");
  if (proto)
    ssa_inp->sin_port = htons(proto->p_proto);
  else
    ssa_inp->sin_port = htons(88);

  memset (&lsa, 0, sizeof(lsa));
  lsa_inp->sin_family = AF_INET;
  lsa_inp->sin_addr.s_addr = htonl(INADDR_ANY);

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0)
    return !SHISHI_OK;

  if (bind(sockfd, (struct sockaddr*)&lsa, sizeof(lsa)) != 0)
    {
      close(sockfd);
      return !SHISHI_OK;
    }
  
  bytes_sent = sendto(sockfd, (void*) indata, inlen, 0, 
		      (struct sockaddr*)&ssa, sizeof(ssa));
  if (bytes_sent != inlen)
    return !SHISHI_OK;

  total_received = 0;
  do
    {
      bytes_received = recvfrom(sockfd, outdata + total_received, 
				*outlen - total_received, 0, 
				(struct sockaddr*)&from_sa, &length);
      total_received += bytes_received;

      FD_ZERO (&readfds);
      FD_SET (sockfd, &readfds);
    }
  while(select(sockfd + 1, &readfds, NULL, NULL, &timeout) == 1);

  close(sockfd);

  *outlen = total_received;

  return SHISHI_OK;
}

int
shishi_kdc_sendrecv (Shishi * handle,
		     char *indata,
		     int inlen, char *outdata, int * outlen)
{
  return shishi_sendrecv_udp (handle->kdc, indata, inlen, outdata, outlen);
}
