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

#include "config.h"

#include <string.h>

#include <sys/select.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <netdb.h>

#include "internal.h"

#if HAVE_GNET
#include <glib.h>
#include <gnet/gnet.h>

int
shishi_kdc_sendrecv_udp (Shishi * handle,
			 char *indata,
			 int inlen, char *outdata, int * outlen)
{
  struct protoent *proto;
  GInetAddr *addr = NULL;
  GUdpSocket *socket = NULL;
  guint n;
  gint port;
  GIOChannel *iochannel = NULL;
  GUdpPacket *packet;
  gint rv;
  GIOError error = G_IO_ERROR_NONE;

  proto = getprotobyname ("kerberos");
  if (proto)
    port = proto->p_proto;
  else
    port = 88;

  /* Create the address */
  addr = gnet_inetaddr_new (handle->kdc, port);
  g_assert (addr != NULL);

  /* Create the socket */
  socket = gnet_udp_socket_new ();
  g_assert (socket != NULL);

  /* Get the IOChannel */
  iochannel = gnet_udp_socket_get_iochannel (socket);
  g_assert (iochannel != NULL);

  /* Create packet */
  packet = gnet_udp_packet_send_new (indata, inlen, addr);

  /* Send packet */
  rv = gnet_udp_socket_send (socket, packet);
  g_assert (rv == 0);
  gnet_udp_packet_delete (packet);

  /* Receive packet */
  n = 0;
  packet = gnet_udp_packet_receive_new (outdata, *outlen);
  *outlen = 0;
  do
    {
      n = gnet_udp_socket_receive (socket, packet);
      if (n == 0)
	{
	  printf ("read nothing\n");
	}
      *outlen += n;
    }
  while (gnet_udp_socket_has_packet (socket));

  gnet_inetaddr_delete (packet->addr);
  gnet_udp_packet_delete (packet);

  gnet_inetaddr_delete (addr);
  gnet_udp_socket_delete (socket);

  return SHISHI_OK;
}

#else

int
shishi_kdc_sendrecv_udp (Shishi * handle,
			 char *indata,
			 int inlen, char *outdata, int * outlen)
{

  return !SHISHI_OK;
}

#endif

int
shishi_kdc_sendrecv (Shishi * handle,
		     char *indata,
		     int inlen, char *outdata, int * outlen)
{
  return shishi_kdc_sendrecv_udp (handle, indata, inlen, outdata, outlen);
}
