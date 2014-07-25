/* resolv.c --- Resolver glue.
 * Copyright (C) 2003-2013 Simon Josefsson
 * Copyright (C) 2002 Jeremie Miller, Thomas Muldowney,
 *                    Ryan Eatmon, Robert Norris
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

/* This file is based on resolver.h from jabberd - Jabber Open Source
 * Server, licensed under GPL.  See:
 *
 * http://www.jabberstudio.org/cgi-bin/viewcvs.cgi/jabberd2/resolver/
 */

#include "internal.h"

#ifdef HAVE_RES_QUERY

#include <netinet/in.h>
# ifdef HAVE_ARPA_NAMESER_H
#  include <arpa/nameser.h>
# endif
# ifdef HAVE_RESOLV_H
#  include <resolv.h>
# endif

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
txt_rr (dns_packet_t packet, unsigned char *eom, unsigned char **scan)
{
  size_t len = (size_t) ** scan;
  char *p;

  p = xmalloc (len + 1);
  memcpy (p, *scan + 1, len);
  p[len] = '\0';
  *scan += (unsigned char) (len + 1);

  return p;
}

static void *
srv_rr (dns_packet_t packet, unsigned char *eom, unsigned char **scan)
{
  unsigned int priority, weight, port;
  int len;
  char host[256];
  Shishi_dns_srv srv;

  GETSHORT (priority, *scan);
  GETSHORT (weight, *scan);
  GETSHORT (port, *scan);

  len = dn_expand (packet.buf, eom, *scan, host, 256);
  if (len < 0)
    return NULL;
  *scan = (unsigned char *) (*scan + len);

  srv = xmalloc (sizeof (*srv));

  srv->priority = priority;
  srv->weight = weight;
  srv->port = port;

  strcpy (srv->name, host);

  return (void *) srv;
}

/* compare two srv structures, order by priority then by randomised weight */
static int
srv_compare (const void *a, const void *b)
{
  Shishi_dns_srv aa, bb;

  if (a == NULL)
    return 1;
  if (b == NULL)
    return -1;

  aa = (*((Shishi_dns *) a))->rr;
  bb = (*((Shishi_dns *) b))->rr;

  if (aa->priority > bb->priority)
    return 1;
  if (aa->priority < bb->priority)
    return -1;

  if (aa->weight > bb->weight)
    return -1;
  if (aa->weight < bb->weight)
    return 1;

  return 0;
}

/**
 * shishi_resolv:
 * @zone: Domain name of authentication zone, e.g. "EXAMPLE.ORG"
 * @querytype: Type of domain data to query for.
 *
 * Queries the DNS resolver for data of type @querytype about
 * the domain name @zone.  Currently, the types %SHISHI_DNS_TXT
 * and %SHISHI_DNS_SRV are the only supported kinds.
 *
 * After its use, the returned list should be deallocated by
 * a call to shishi_resolv_free().
 *
 * Return value: Returns a linked list of DNS resource records,
 *   or %NULL if the query failed.
 **/
Shishi_dns
shishi_resolv (const char *zone, uint16_t querytype)
{
  char host[256];
  dns_packet_t packet;
  int len, qdcount, ancount, an, n;
  unsigned char *eom, *scan;
  Shishi_dns *reply, first;
  uint16_t type, class, ttl;

  if (zone == NULL || *zone == '\0')
    return NULL;

  switch (querytype)
    {
    case SHISHI_DNS_TXT:
    case SHISHI_DNS_SRV:
      break;

    default:
      return NULL;
    }

  /* do the actual query */
  if ((len = res_query (zone, C_IN, querytype, packet.buf, MAX_PACKET)) < 0
      || len < (int) sizeof (HEADER))
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
  reply = xcalloc (ancount, sizeof (Shishi_dns));

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
      if (type != querytype)
	{
	  scan = (unsigned char *) (scan + len);
	  continue;
	}

      /* create a new reply structure to save it in */
      reply[an] = xmalloc (sizeof (*reply[0]));

      reply[an]->type = type;
      reply[an]->class = class;
      reply[an]->ttl = ttl;

      reply[an]->next = NULL;

      /* type-specific processing */
      switch (type)
	{
	case SHISHI_DNS_TXT:
	  reply[an]->rr = txt_rr (packet, eom, &scan);
	  break;

	case SHISHI_DNS_SRV:
	  reply[an]->rr = srv_rr (packet, eom, &scan);
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
  if (querytype == SHISHI_DNS_SRV)
    qsort (reply, an, sizeof (Shishi_dns), srv_compare);

  /* build a linked list out of the array elements */
  for (n = 0; n < an - 1; n++)
    reply[n]->next = reply[n + 1];

  first = reply[0];

  free (reply);

  return first;
}

#else /* !HAVE_RES_QUERY */

Shishi_dns
shishi_resolv (const char *zone, uint16_t querytype)
{
  return NULL;
}

#endif

/**
 * shishi_resolv_free:
 * @rrs: List of DNS RRs as returned by shishi_resolv().
 *
 * Deallocates a list of DNS resource records returned by
 * a call to shishi_resolv().
 **/
void
shishi_resolv_free (Shishi_dns rrs)
{
  Shishi_dns next;

  while (rrs != NULL)
    {
      next = rrs->next;
      free (rrs->rr);
      free (rrs);
      rrs = next;
    }
}
