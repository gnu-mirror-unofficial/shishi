/* resolver.h --- Resolver glue prototypes.
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

/* older systems might not have these */
#ifndef T_SRV
# define T_SRV (33)
#endif

typedef struct dnshost_st
{
  struct dnshost_st *next;

  unsigned int type;
  unsigned int class;
  unsigned int ttl;

  void *rr;
} *dnshost_t;

typedef struct dns_srv_st
{
  unsigned int priority;
  unsigned int weight;
  unsigned int port;
  unsigned int rweight;

  char name[256];
} *dns_srv_t;

dnshost_t _shishi_resolv (const char *zone, unsigned int type);
void _shishi_resolv_free (dnshost_t dns);
