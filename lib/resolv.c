/* resolv.c	resolver glue.
 * Copyright (C) 2003  Simon Josefsson
 * Copyright (c) 2002 Jeremie Miller, Thomas Muldowney,
 *                    Ryan Eatmon, Robert Norris
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

/* This file comes from jabberd - Jabber Open Source Server, licensed
   under GPL. http://www.jabberstudio.org/cgi-bin/viewcvs.cgi/jabberd2/ */

#include "internal.h"

#ifdef HAVE_LIBRESOLV

/* the largest packet we'll send and receive */
#if PACKETSZ > 1024
# define MAX_PACKET PACKETSZ
#else
# define MAX_PACKET (1024)
#endif

typedef union
{
  HEADER hdr;
  unsigned char buf[MAX_PACKET];
} dns_packet_t;

static void *
_a_rr (dns_packet_t packet, unsigned char *eom, unsigned char **scan)
{
  struct in_addr in;

  GETLONG (in.s_addr, *scan);
  in.s_addr = ntohl (in.s_addr);

  return xstrdup (inet_ntoa (in));
}

static void *
_srv_rr (dns_packet_t packet, unsigned char *eom, unsigned char **scan)
{
  unsigned int priority, weight, port;
  int len;
  char host[256];
  dns_srv_t srv;

  GETSHORT (priority, *scan);
  GETSHORT (weight, *scan);
  GETSHORT (port, *scan);

  len = dn_expand (packet.buf, eom, *scan, host, 256);
  if (len < 0)
    return NULL;
  *scan = (unsigned char *) (*scan + len);

  srv = (dns_srv_t) xmalloc (sizeof (struct dns_srv_st));

  srv->priority = priority;
  srv->weight = weight;
  srv->port = port;

  /* figure out the randomised weight */
  /* !!! this seems wrong, but I don't have the RFC on hand */
  if (weight != 0)
    srv->rweight = 1 + random () % (10000 * weight);
  else
    srv->rweight = 0;

  strcpy (srv->name, host);

  return (void *) srv;
}

static void *
_txt_rr (dns_packet_t packet, unsigned char *eom, unsigned char **scan)
{
  size_t len = (size_t)**scan;
  char *p;

  p = xmalloc (len);
  memcpy (p, *scan + 1, len);
  *scan += (unsigned char) (len + 1);

  return p;
}

/* compare two srv structures, order by priority then by randomised weight */
static int
_srv_compare (const void *a, const void *b)
{
  dns_srv_t aa, bb;

  if (a == NULL)
    return 1;
  if (b == NULL)
    return -1;

  aa = (dns_srv_t) (*((dnshost_t *) a))->rr;
  bb = (dns_srv_t) (*((dnshost_t *) b))->rr;

  if (aa->priority > bb->priority)
    return 1;
  if (aa->priority < bb->priority)
    return -1;

  if (aa->rweight > bb->rweight)
    return -1;
  if (aa->rweight < bb->rweight)
    return 1;

  return 0;
}

/* the actual resolver function */
dnshost_t
_shishi_resolv (const char *zone, unsigned int query_type)
{
  char host[256];
  dns_packet_t packet;
  int len, qdcount, ancount, an, n;
  unsigned char *eom, *scan;
  dnshost_t *reply, first;
  unsigned int type, class, ttl;

  if (zone == NULL || *zone == '\0')
    return NULL;

  switch (query_type)
    {
    case T_A:
    case T_TXT:
    case T_SRV:
      break;

    default:
      return NULL;
    }

  /* do the actual query */
  if ((len = res_query (zone, C_IN, query_type, packet.buf, MAX_PACKET)) < 0
      || len < (int)sizeof (HEADER))
    return NULL;

  /* we got a valid result, containing two types of records - packet
   * and answer .. we have to skip over the packet records */

  /* no. of packets, no. of answers */
  qdcount = ntohs (packet.hdr.qdcount);
  ancount = ntohs (packet.hdr.ancount);

  /* end of the returned message */
  eom = (unsigned char *) (packet.buf + len);

  /* our current location */
  scan = (unsigned char *) (packet.buf + sizeof (HEADER));

  /* skip over the packet records */
  while (qdcount > 0 && scan < eom)
    {
      qdcount--;
      if ((len = dn_expand (packet.buf, eom, scan, host, 256)) < 0)
	return NULL;
      scan = (unsigned char *) (scan + len + QFIXEDSZ);
    }

  /* create an array to store the replies in */
  reply = (dnshost_t *) xmalloc (sizeof (dnshost_t) * ancount);
  memset (reply, 0, sizeof (dnshost_t) * ancount);

  an = 0;
  /* loop through the answer buffer and extract SRV records */
  while (ancount > 0 && scan < eom)
    {
      ancount--;
      len = dn_expand (packet.buf, eom, scan, host, 256);
      if (len < 0)
	{
	  for (n = 0; n < an; n++)
	    free (reply[n]);
	  free (reply);
	  return NULL;
	}

      scan += len;

      /* extract the various parts of the record */
      GETSHORT (type, scan);
      GETSHORT (class, scan);
      GETLONG (ttl, scan);
      GETSHORT (len, scan);

      /* skip records we're not interested in */
      if (type != query_type)
	{
	  scan = (unsigned char *) (scan + len);
	  continue;
	}

      /* create a new reply structure to save it in */
      reply[an] = (dnshost_t) xmalloc (sizeof (struct dnshost_st));

      reply[an]->type = type;
      reply[an]->class = class;
      reply[an]->ttl = ttl;

      reply[an]->next = NULL;

      /* type-specific processing */
      switch (type)
	{
	case T_A:
	  reply[an]->rr = _a_rr (packet, eom, &scan);
	  break;

	case T_TXT:
	  reply[an]->rr = _txt_rr (packet, eom, &scan);
	  break;

	case T_SRV:
	  reply[an]->rr = _srv_rr (packet, eom, &scan);
	  break;

	default:
	  scan = (unsigned char *) (scan + len);
	  continue;
	}

      /* fell short, we're done */
      if (reply[an]->rr == NULL)
	{
	  free (reply[an]);
	  reply[an] = NULL;
	  break;
	}

      /* on to the next one */
      an++;
    }

  /* sort srv records them */
  if (query_type == T_SRV)
    qsort (reply, an, sizeof (dnshost_t), _srv_compare);

  /* build a linked list out of the array elements */
  for (n = 0; n < an - 1; n++)
    reply[n]->next = reply[n + 1];

  first = reply[0];

  free (reply);

  return first;
}

/* free an srv structure */
void
_shishi_resolv_free (dnshost_t dns)
{
  dnshost_t next;

  while (dns != NULL)
    {
      next = dns->next;
      free (dns->rr);
      free (dns);
      dns = next;
    }
}

#else

dnshost_t
_shishi_resolv (const char *zone, unsigned int query_type)
{
  return NULL;
}

void
_shishi_resolv_free (dnshost_t dns)
{
}

#endif
