/* server.c	sample network server using shishi
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
server (Shishi * handle, struct arguments arg)
{
  Shishi_ap *ap;
  Shishi_ticket *tkt;
  ASN1_TYPE apreq, aprep, ticket, encticketpart, authenticator;
  Shishi_key *key, *key2;
  int keytype;
  char salt[BUFSIZ];
  int res;
  char cnamerealm[BUFSIZ];
  int cnamerealmlen;

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
      printf ("Ticket granter: `%s'\n", arg.tgtname);
      printf ("Service name: `%s'\n", arg.sname);
    }

  if (arg.algorithm == 0)
    {
      arg.algorithm = SHISHI_DES_CBC_MD5;

      if (!arg.silent)
	fprintf (stderr, "No algorithm specified, defaulting to %s\n",
		 shishi_cipher_name (arg.algorithm));
    }

  if (arg.password)
    {
      if (strlen (arg.realm) + strlen (arg.sname) > sizeof (salt))
	{
	  fprintf (stderr, _("Too long realm/principal...\n"));
	  return 1;
	}
      strcpy (salt, arg.realm);
      strcat (salt, arg.sname);

      res = shishi_key_from_string (handle,
				    arg.algorithm,
				    arg.password,
				    strlen (arg.password),
				    salt, strlen (salt), arg.parameter, &key);
      if (res != SHISHI_OK)
	{
	  fprintf (stderr, _("Error in string2key: %s\n"),
		   shishi_strerror_details (handle));
	  return 1;
	}

    }
  else if (arg.keyvalue)
    {
      res = shishi_key_from_base64 (handle, arg.algorithm, arg.keyvalue, &key);
      if (res != SHISHI_OK)
	{
	  fprintf (stderr, _("Could not create key: %s\n"),
		   shishi_strerror (res));
	  return res;
	}
    }
  else
    {
      key = shishi_hostkeys_for_localservice (handle, "host");
      if (key == NULL)
	{
	  fprintf (stderr, "Could not find key: %s\n",
		   shishi_strerror_details (handle));
	  return 1;
	}
    }

  res = shishi_apreq_parse (handle, stdin, &apreq);
  if (res != SHISHI_OK)
    {
      fprintf (stderr, _("Could not read AP-REQ:\n%s\n%s\n"),
	       shishi_strerror (res), shishi_strerror_details (handle));
      return 1;
    }

  res = shishi_ap(handle, &ap);
  if (res != SHISHI_OK)
    {
      fprintf (stderr, _("Could not create AP: %s\n"),
	       shishi_strerror (res));
      return 1;
    }

  shishi_ap_req_set (ap, apreq);

  res = shishi_ap_req_process (ap, key);
  if (res != SHISHI_OK)
    {
      fprintf (stderr, "Could not process AP-REQ: %s\n",
	       shishi_strerror (res));
      return 1;
    }


  if (arg.verbose)
    shishi_authenticator_print (handle, stdout, shishi_ap_authenticator(ap));

  cnamerealmlen = sizeof (cnamerealm);
  res = shishi_authenticator_cnamerealm_get (handle,
					     shishi_ap_authenticator(ap),
					     cnamerealm, &cnamerealmlen);
  cnamerealm[cnamerealmlen] = '\0';
  printf ("Client name (from authenticator): %s\n", cnamerealm);

  cnamerealmlen = sizeof (cnamerealm);
  res = shishi_encticketpart_cnamerealm_get (handle,
					     shishi_ticket_encticketpart(shishi_ap_ticket(ap)),
					     cnamerealm, &cnamerealmlen);
  cnamerealm[cnamerealmlen] = '\0';
  printf ("Client name (from encticketpart): %s\n", cnamerealm);

  cnamerealmlen = sizeof (cnamerealm);
  res = shishi_ticket_snamerealm_get (handle, shishi_ap_ticket(ap),
				      cnamerealm, &cnamerealmlen);
  cnamerealm[cnamerealmlen] = '\0';
  printf ("Server name (from ticket): %s\n", cnamerealm);

  printf ("User authenticated.\n");

  if (shishi_apreq_mutual_required_p (handle, apreq))
    {
      ASN1_TYPE aprep;

      printf ("Mutual authentication required.\n");

      res = shishi_ap_rep_asn1(ap, &aprep);
      if (res != SHISHI_OK)
	{
	  fprintf (stderr, "Error creating AP-REP: %s\n",
		   shishi_strerror (res));
	  return 1;
	}

      if (arg.verbose)
	shishi_encapreppart_print (handle, stdout,
				   shishi_last_encapreppart (handle));
      shishi_aprep_print (handle, stdout, aprep);
    }

  return SHISHI_OK;
}
