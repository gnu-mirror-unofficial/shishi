/* ap.c	authentication header
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

int
ap (Shishi * handle, struct arguments arg)
{
  ASN1_TYPE apreq;
  int res;

  if (arg.cname == NULL)
    arg.cname = shishi_principal_default (handle);

  if (arg.realm == NULL)
    arg.realm = shishi_realm_default (handle);

  if (arg.sname == NULL)
    {
      int len = strlen ("krbtgt/") + strlen (arg.realm) + strlen ("@") +
	strlen (arg.realm) + 1;
      arg.sname = malloc (len);
      if (arg.sname == NULL)
	return SHISHI_MALLOC_ERROR;
      sprintf (arg.sname, "krbtgt/%s@%s", arg.realm, arg.realm);
    }

  if (arg.apreqreadfile)
    {
      res = shishi_apreq_from_file (handle, &apreq,
				    arg.apreqreadtype, arg.apreqreadfile);
      if (res != SHISHI_OK)
	{
	  fprintf (stderr, _("Cannot read AP-REQ from file: %s\n"),
		   shishi_strerror_details (handle));
	  return 1;
	}
    }
  else
    {
      unsigned char data[BUFSIZ];
      int datalen;
      Shishi_ticket *ticket;
      int res;

      ticket = shishi_ticketset_find_ticket_for_clientserver (handle,
							      NULL,
							      arg.cname,
							      arg.sname);
      if (ticket == NULL)
	{
	  fprintf (stderr, _("Could not find ticket for `%s' `%s': %s\n"),
		   arg.cname, arg.sname, shishi_strerror_details (handle));
	  return ASN1_TYPE_EMPTY;
	}

      if (arg.verbose)
	shishi_ticket_print (ticket, stdout);

      if (arg.authenticatordata)
	{
	  datalen = shishi_from_base64 (data, arg.authenticatordata);
	  if (datalen <= 0)
	    {
	      fprintf (stderr,
		       "base64 decoding of authenticator data failed\n");
	      return 1;
	    }
	}
      else if (arg.authenticatordatareadfile)
	{
	  fprintf (stderr, "authenticatordatafile not implemented\n");
	  return 1;
	}
      else
	datalen = 0;

      res = shishi_ticket_apreq_data (handle, ticket, data, datalen, &apreq);
      if (res != SHISHI_OK)
	{
	  fprintf (stderr, _("Could not make AP-REQ: %s\n"),
		   shishi_strerror_details (handle));
	  return 1;
	}
    }

  if (arg.authenticatorwritefile && shishi_last_authenticator (handle))
    shishi_authenticator_to_file (handle, shishi_last_authenticator (handle),
				  arg.authenticatorwritetype,
				  arg.authenticatorwritefile);

  if (!arg.silent)
    shishi_apreq_print (handle, stdout, apreq);

  if (arg.apreqwritefile)
    shishi_apreq_to_file (handle, apreq,
			  arg.apreqwritetype, arg.apreqwritefile);

  return 0;
}
