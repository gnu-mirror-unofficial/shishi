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
  Shishi_ap *ap;
  int res;


  if (arg.cname == NULL)
    arg.cname = shishi_principal_default (handle);

  if (arg.realm == NULL)
    arg.realm = shishi_realm_default (handle);

  if (arg.sname == NULL)
    {
      asprintf(&arg.sname, "host/www");
      if (arg.sname == NULL)
	die("Could not allocate server name.");
    }

  if (arg.verbose)
    {
      printf ("Client name: `%s'\n", arg.cname);
      printf ("Realm: `%s'\n", arg.realm);
      printf ("Service name: `%s'\n", arg.sname);
    }

  if (arg.apreqreadfile)
    {
      ASN1_TYPE apreq;

      res = shishi_apreq_from_file (handle, &apreq,
				    arg.apreqreadtype, arg.apreqreadfile);
      if (res != SHISHI_OK)
	{
	  fprintf (stderr, _("Cannot read AP-REQ from file: %s\n"),
		   shishi_strerror_details (handle));
	  return 1;
	}
      res = shishi_ap (handle, &ap);
      if (res != SHISHI_OK)
	{
	  fprintf (stderr, _("Could not make AP-REQ: %s\n"),
		   shishi_strerror_details (handle));
	  return 1;
	}
      shishi_ap_req_set (ap, apreq);
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
	  fprintf (stderr,
		   _("Could not find ticket for `%s', use --server-name\n"),
		   arg.sname);
	  return 1;
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

      res = shishi_ap_tktoptionsdata (handle, &ap, ticket, 0, data, datalen);
      if (res != SHISHI_OK)
	{
	  fprintf (stderr, _("Could not make AP-REQ: %s\n"),
		   shishi_strerror_details (handle));
	  return 1;
	}

      res = shishi_ap_req_build (ap);
      if (res != SHISHI_OK)
	{
	  fprintf (stderr, _("Could not build AP-REQ: %s\n"),
		   shishi_strerror_details (handle));
	  return 1;
	}
    }

  if (shishi_ap_authenticator(ap))
    shishi_authenticator_print (handle, stdout, shishi_ap_authenticator(ap));

  if (arg.authenticatorwritefile && shishi_ap_authenticator(ap))
    shishi_authenticator_to_file (handle, shishi_ap_authenticator(ap),
				  arg.authenticatorwritetype,
				  arg.authenticatorwritefile);

  if (!arg.silent)
    shishi_apreq_print (handle, stdout, shishi_ap_req(ap));

  if (arg.apreqwritefile)
    shishi_apreq_to_file (handle, shishi_ap_req(ap),
			  arg.apreqwritetype, arg.apreqwritefile);

  return 0;
}
