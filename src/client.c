/* client.c	sample network client using shishi
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

#include "data.h"

#define SERVER_NAME "sample"

int
client (Shishi * handle, Shishi_ticketset * ticketset, struct arguments arg)
{
  Shishi_ticket *tkt, *tmptkt;
  ASN1_TYPE apreq;
  int res;

  if (arg.cname == NULL)
    arg.cname = shishi_principal_default_get (handle);

  if (arg.realm == NULL)
      arg.realm = shishi_realm_default_get (handle);

  if (arg.sname == NULL)
    {
      int len = strlen (SERVER_NAME"/") + strlen (arg.realm) + 1;
      arg.sname = malloc (len);
      if (arg.sname == NULL)
	return SHISHI_MALLOC_ERROR;
      sprintf (arg.sname, "%s/%s", SERVER_NAME, arg.realm);
    }

  if (arg.tgtname == NULL)
    {
      int len = strlen ("krbtgt/") + strlen (arg.realm) + 1;
      arg.tgtname = malloc (len);
      if (arg.tgtname == NULL)
	return SHISHI_MALLOC_ERROR;
      sprintf (arg.tgtname, "krbtgt/%s", arg.realm);
    }
  
  if (arg.verbose)
    {
      printf("Client name: `%s'\n", arg.cname);
      printf("Realm: `%s'\n", arg.realm);
      printf("Ticket granter: `%s'\n", arg.tgtname);
      printf("Service name: `%s'\n", arg.sname);
    }


  tkt = shishi_ticketset_find_ticket_for_clientserver (handle, ticketset,
						       arg.cname, arg.sname);
  if (tkt == NULL)
    {
      ASN1_TYPE req, rep;

      tkt = shishi_ticketset_find_ticket_for_clientserver (handle, ticketset,
							   arg.cname, 
							   arg.tgtname);
      if (tkt == NULL)
	req = shishi_asreq (handle, arg.realm, arg.sname, arg.cname);
      else
	req = shishi_tgsreq (handle, arg.realm, arg.sname, tkt);

      res = shishi_kdcreq_sendrecv (handle, req, &rep);
      if (res != SHISHI_OK)
	{
	  printf ("Could not send to KDC: %s\n", shishi_strerror (res));
	  return res;
	}

      res = kdc_response (handle, arg, req, rep, tkt, &tmptkt);
      if (res != 0)
	return res;

      res = shishi_ticketset_add (handle, ticketset, tmptkt);
      if (res != SHISHI_OK)
	{
	  printf ("Could not add ticket: %s", shishi_strerror (res));
	  return res;
	}
      tkt = tmptkt;
    }

  puts("foo");

  res = shishi_ticket_apreq_data (handle, tkt, NULL, 0, &apreq);
  if (res != SHISHI_OK)
    {
      printf ("Could not create AP-REQ: %s", shishi_strerror (res));
      return res;
    }

  res = shishi_apreq_options_set (handle, apreq, arg.apoptions);
  if (res != SHISHI_OK)
    {
      printf ("Could not set AP-Options: %s", shishi_strerror (res));
      return res;
    }

  if (arg.verbose)
    shishi_authenticator_print (handle, stdout,
				shishi_last_authenticator (handle));

  shishi_apreq_print(handle, stdout, apreq);

  return SHISHI_OK;
}
