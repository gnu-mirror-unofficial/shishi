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

#define SERVER_NAME "sample"

int
server (Shishi * handle, Shishi_ticketset * ticketset, struct arguments arg)
{
  Shishi_ticket *tkt;
  ASN1_TYPE apreq, aprep, ticket, encticketpart, authenticator;
  unsigned char key[BUFSIZ];
  int keylen = sizeof (key);
  int keytype;
  char salt[BUFSIZ];
  int res;
  char cnamerealm[BUFSIZ];
  int cnamerealmlen;

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

  if (arg.algorithm == 0)
    {
      arg.algorithm = SHISHI_DES_CBC_MD5;

      if (!arg.silent)
	fprintf (stderr, "No algorithm specified, defaulting to %s\n",
		 shishi_cipher_name (arg.algorithm));
    }

  if (arg.stringtokey)
    {
      if (strlen (arg.realm) + strlen (arg.sname) > sizeof (salt))
	{
	  fprintf (stderr, _("Too long realm/principal...\n"));
	  return 1;
	}
      strcpy (salt, arg.realm);
      strcat (salt, arg.sname);

      res = shishi_string_to_key (handle,
				  arg.algorithm,
				  arg.stringtokey,
				  strlen (arg.stringtokey),
				  salt,
				  strlen (salt), key, &keylen);
      if (res != SHISHI_OK)
	{
	  fprintf (stderr, _("Error in string2key: %s\n"),
		   shishi_strerror_details (handle));
	  return 1;
	}

    }
  else if (arg.keyvalue)
    {
      if (strlen (arg.keyvalue) > sizeof (key))
	{
	  fprintf (stderr, "keyvalue too large\n");
	  return 1;
	}
      keylen = shishi_from_base64 (key, arg.keyvalue);
      if (keylen <= 0)
	{
	  fprintf (stderr, "base64 decoding of key value failed\n");
	  return 1;
	}
    }
  else
    {
      printf("No key\n");
      return 1;
    }

  res = shishi_apreq_parse(handle, stdin, &apreq);
  if (res != SHISHI_OK)
    {
      fprintf (stderr, _("Could not read AP-REQ:\n%s\n%s\n"),
	       shishi_strerror (res),
	       shishi_strerror_details (handle));
      return 1;
    }

  res = shishi_apreq_get_ticket(handle, apreq, &ticket);
  if (res != SHISHI_OK)
    {
      fprintf (stderr, _("Could not extract ticket:\n%s\n%s\n"),
	       shishi_strerror (res),
	       shishi_strerror_details (handle));
      return 1;
    }

  if (arg.verbose)
    {
      puts("Read:");

      shishi_apreq_print(handle, stdout, apreq);
      shishi_asn1ticket_print(handle, stdout, ticket);
    }

  res = shishi_ticket_decrypt (handle, ticket, arg.algorithm, key, keylen,
			       &encticketpart);
  if (res != SHISHI_OK)
    {
      fprintf (stderr, _("Error decrypting ticket: %s\n"),
	       shishi_strerror_details (handle));
      return 1;
    }

  if (arg.verbose)
    asn1_print_structure (stdout, encticketpart, encticketpart->name, 
			  ASN1_PRINT_NAME_TYPE_VALUE);

  res = shishi_encticketpart_get_key (handle, encticketpart, &keytype,
				      key, &keylen);
  if (res != SHISHI_OK)
    {
      fprintf (stderr, _("EncTicketPart get key failed: %s\n"),
	       shishi_strerror_details (handle));
      return 1;
    }

  res = shishi_apreq_decrypt (handle, apreq, arg.algorithm, key, keylen,
			      &authenticator);
  if (res != SHISHI_OK)
    {
      fprintf (stderr, _("Error decrypting apreq:%s\n%s\n"),
	       shishi_strerror (res),
	       shishi_strerror_details (handle));
      return 1;
    }

  if (arg.verbose)
    asn1_print_structure (stdout, authenticator, authenticator->name, 
			  ASN1_PRINT_NAME_TYPE_VALUE);

  cnamerealmlen = sizeof(cnamerealm);
  res = shishi_authenticator_cnamerealm_get (handle, authenticator, 
					     cnamerealm, &cnamerealmlen);
  cnamerealm[cnamerealmlen] = '\0';
  printf("Client name (from authenticator): %s\n", cnamerealm);

  cnamerealmlen = sizeof(cnamerealm);
  res = shishi_encticketpart_cnamerealm_get (handle, encticketpart, 
					     cnamerealm, &cnamerealmlen);
  cnamerealm[cnamerealmlen] = '\0';
  printf("Client name (from encticketpart): %s\n", cnamerealm);

  cnamerealmlen = sizeof(cnamerealm);
  res = shishi_ticket_snamerealm_get (handle, ticket, 
				      cnamerealm, &cnamerealmlen);
  cnamerealm[cnamerealmlen] = '\0';
  printf("Server name (from ticket): %s\n", cnamerealm);

  printf("User authenticated.\n");

  if (shishi_apreq_mutual_required_p (handle, apreq))
    {
      ASN1_TYPE encapreppart, aprep;

      printf("Mutual authentication required.\n");

      aprep = shishi_aprep (handle);
      res = shishi_aprep_enc_part_make (handle, aprep, 
					authenticator, encticketpart);
      if (arg.verbose)
	shishi_encapreppart_print (handle, stdout, 
				   shishi_last_encapreppart(handle));
      shishi_aprep_print (handle, stdout, aprep);
    }

  return SHISHI_OK;
}
