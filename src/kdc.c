/* kdc.c	low-level authentication (AS and TGS) services
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
kdc_write_apreq (Shishi * handle, struct arguments arg, ASN1_TYPE req)
{
  int res, i, n;

  res = asn1_number_of_elements (req, "KDC-REQ.padata", &n);
  if (res == ASN1_ELEMENT_NOT_FOUND)
    n = 0;
  else if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  printf (_("Found %d PA-DATAs...\n"), n);

  for (i = 1; i <= n; i++)
    {
      unsigned char patype;
      int patypelen;
      ASN1_TYPE apreq;
      char format[BUFSIZ];
      char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
      char der[BUFSIZ];
      int derlen;
      int l;

      sprintf (format, "KDC-REQ.padata.?%d.padata-type", i);
      patypelen = sizeof (patype);
      res = asn1_read_value (req, format, &patype, &patypelen);
      if (res != ASN1_SUCCESS)
	{
	  fprintf (stdout, libtasn1_strerror (res));
	  return SHISHI_ASN1_ERROR;
	}

      if (patype == SHISHI_PA_TGS_REQ)
	{
	  sprintf (format, "KDC-REQ.padata.?%d.padata-value", i);
	  derlen = sizeof (der);
	  res = asn1_read_value (req, format, der, &derlen);
	  if (res != ASN1_SUCCESS)
	    {
	      fprintf (stdout, libtasn1_strerror (res));
	      return SHISHI_ASN1_ERROR;
	    }

	  apreq = shishi_d2a_apreq (handle, der, derlen, errorDescription);
	  if (apreq == ASN1_TYPE_EMPTY)
	    {
	      fprintf (stdout, "Could not DER deocde AP-REQ\n");
	      return SHISHI_ASN1_ERROR;
	    }

	  if (arg.apreqwritefile)
	    shishi_apreq_to_file (handle, apreq,
				  arg.apreqwritetype, arg.apreqwritefile);

	  break;
	}
    }

  return SHISHI_OK;
}

int
kdc_response (Shishi * handle,
	      struct arguments arg,
	      ASN1_TYPE req, ASN1_TYPE rep,
	      Shishi_ticket * oldtkt, Shishi_ticket ** newtkt)
{
  ASN1_TYPE kdcreppart = ASN1_TYPE_EMPTY;
  ASN1_TYPE ticket = ASN1_TYPE_EMPTY;
  int res;

  if (arg.keyvalue && arg.algorithm)
    {
      unsigned char buf[BUFSIZ];
      int keylen;
      int keytype;
      Shishi_key *key;

      res = shishi_key_from_base64 (handle, arg.algorithm, arg.keyvalue, &key);
      if (res != SHISHI_OK)
	{
	  fprintf (stderr, _("Could not create key: %s\n"),
		   shishi_strerror (res));
	  return res;
	}

      res = shishi_kdc_process (handle, req, rep, key,
				oldtkt ? 3 : 8, &kdcreppart);
    }
  else if (oldtkt)
    res = shishi_tgs_process (handle, req, rep,
			      shishi_ticket_enckdcreppart (oldtkt),
			      &kdcreppart);
  else if (arg.password)
    res = shishi_as_process (handle, req, rep, arg.password, &kdcreppart);
  else if (isatty (fileno (stdin)))
    {
      char user[BUFSIZ];
      int userlen;
      char password[BUFSIZ];

      userlen = sizeof (user);
      shishi_kdcreq_cnamerealm_get (handle, req, user, &userlen);
      user[userlen] = '\0';

      res = shishi_prompt_password (handle, stdin, password, BUFSIZ,
				    stdout, "Enter password for `%s': ",
				    user);

      if (res == SHISHI_OK)
	res = shishi_as_process (handle, req, rep, password, &kdcreppart);
    }
  else
    {
      fprintf (stderr, "Unable to locate key.  Do a TGS request, use "
	       "--string-to-key for AS\nrequests, or specify the raw key "
	       "using --keyvalue and --algorithm.\n");
      return 1;
    }

  if (res != SHISHI_OK)
    {
      fprintf (stderr, _("AS process failed: %s\n%s"), shishi_strerror (res),
	       shishi_strerror_details (handle));
      return res;
    }

  res = shishi_kdcrep_get_ticket (handle, rep, &ticket);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not extract ticket from AS-REP: %s",
			   shishi_strerror_details (handle));
      return res;
    }

  *newtkt = shishi_ticket (handle, "jas@JOSEFSSON.ORG", ticket, kdcreppart);
  if (*newtkt == NULL)
    {
      printf ("Could not create ticket\n");
      return SHISHI_MALLOC_ERROR;
    }

  return SHISHI_OK;
}

int
kdc (Shishi * handle, struct arguments arg)
{
  ASN1_TYPE req = ASN1_TYPE_EMPTY;
  ASN1_TYPE rep = ASN1_TYPE_EMPTY;
  Shishi_ticket *oldtkt;
  Shishi_ticket *newtkt;
  int res;
  Shishi_as *as;

  if (arg.cname == NULL)
    arg.cname = shishi_principal_default (handle);

  if (arg.realm == NULL)
    arg.realm = shishi_realm_default (handle);

  if (arg.sname == NULL)
    {
      int len = strlen ("krbtgt/") + strlen (arg.realm) + 1;
      arg.sname = malloc (len);
      if (arg.sname == NULL)
	return SHISHI_MALLOC_ERROR;
      sprintf (arg.sname, "krbtgt/%s", arg.realm);
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
      printf ("Client name: `%s'\n", arg.cname);
      printf ("Realm: `%s'\n", arg.realm);
      printf ("Ticket granter: `%s'\n", arg.tgtname);
      printf ("Service name: `%s'\n", arg.sname);
    }

  if (!arg.request_p && !arg.sendrecv_p && !arg.response_p)
    {
      arg.request_p = 1;
      arg.sendrecv_p = 1;
      arg.response_p = 1;
    }

  if (arg.forceas_p)
    {
      if (!arg.silent)
	printf (_("Forcing AS mode...\n"));
      oldtkt = NULL;
    }
  else
    {
      oldtkt = shishi_ticketset_find_ticket_for_clientserver (handle,
							      NULL,
							      arg.cname,
							      arg.tgtname);
      if (arg.forcetgs_p && oldtkt == NULL)
	{
	  printf ("Could not find ticket for TGS\n");
	  return 1;
	}

      if (!arg.silent)
	if (oldtkt)
	  {
	    fprintf (stderr, "Found ticket, doing TGS...\n");
	    if (arg.verbose)
	      shishi_ticket_print (oldtkt, stdout);
	  }
	else
	  fprintf (stderr, "No usable ticket, doing AS...\n");
    }

  /* Get request */

  if (!arg.silent)
    printf ("Generating KDC-REQ...\n");

  if (arg.kdcreqreadfile)
    {
      res = shishi_kdcreq_from_file (handle, &req,
				     arg.kdcreqreadtype, arg.kdcreqreadfile);
      if (res != SHISHI_OK)
	{
	  printf ("Could not read KDC-REQ: %s", shishi_strerror (res));
	  return res;
	}

      if (arg.apreqwritefile)
	kdc_write_apreq (handle, arg, req);
    }
  else if (arg.request_p)
    {
      if (oldtkt == NULL)
	req = shishi_asreq_rsc (handle, arg.realm, arg.sname, arg.cname);
      else
	req = shishi_tgsreq_rst (handle, arg.realm, arg.sname, oldtkt);

      if (req == ASN1_TYPE_EMPTY)
	{
	  printf ("Could not generate KDC-REQ: %s",
		  shishi_strerror_details (handle));
	  return 1;
	}

      if (oldtkt)
	{
	  if (arg.verbose)
	    shishi_authenticator_print (handle, stdout,
					shishi_last_authenticator (handle));

	  if (arg.authenticatorwritefile)
	    shishi_authenticator_to_file (handle,
					  shishi_last_authenticator (handle),
					  arg.authenticatorwritetype,
					  arg.authenticatorwritefile);

	  if (arg.verbose)
	    shishi_apreq_print (handle, stdout, shishi_last_apreq (handle));

	  if (arg.apreqwritefile)
	    shishi_apreq_to_file (handle, shishi_last_apreq (handle),
				  arg.apreqwritetype, arg.apreqwritefile);
	}

      if (!arg.sendrecv_p && !arg.response_p)
	return 0;
    }
  else if (arg.sendrecv_p || arg.response_p)
    {
      fprintf
	(stderr,
	 _("Request required, use --request or --read-kdc-request-file\n"));
      return 1;
    }

  if (arg.verbose)
    shishi_kdcreq_print (handle, stdout, req);

  if (arg.kdcreqwritefile)
    shishi_kdcreq_to_file (handle, req,
			   arg.kdcreqwritetype, arg.kdcreqwritefile);

  if (!arg.silent)
    printf ("Generating KDC-REQ...done\n");

  /* Get response for request */

  if (!arg.silent)
    printf ("Sending KDC-REQ and receiving KDC-REP...\n");

  if (arg.kdcrepreadfile)
    {
      res = shishi_kdcrep_from_file (handle, &rep,
				     arg.kdcrepreadtype, arg.kdcrepreadfile);
      if (res != SHISHI_OK)
	return res;
    }
  else if (arg.sendrecv_p)
    {
      res = shishi_kdcreq_sendrecv (handle, req, &rep);
      if (res != SHISHI_OK)
	{
	  printf ("Could not send to KDC: %s\n", shishi_strerror (res));
	  return res;
	}

      if (!arg.response_p)
	return 0;
    }
  else if (arg.response_p)
    {
      fprintf (stderr,
	       _("Response required, use --sendrecv or --response-file\n"));
      return 1;
    }

  if (arg.verbose)
    shishi_kdcrep_print (handle, stdout, rep);

  if (arg.kdcrepwritefile)
    shishi_kdcrep_to_file (handle, rep,
			   arg.kdcrepwritetype, arg.kdcrepwritefile);

  if (!arg.silent)
    printf ("Sending KDC-REQ and receiving KDC-REP...done\n");

  /* Process request and response */

  if (!arg.silent)
    printf ("Processing KDC-REP...\n");

  if (arg.response_p)
    {
      res = kdc_response (handle, arg, req, rep, oldtkt, &newtkt);
      if (res != 0)
	return res;
    }

  if (!arg.silent)
    printf ("Processing KDC-REP...done\n");

  /* Add new ticket */

  if (!arg.silent)
    printf ("Adding new ticket...\n");

  res = shishi_ticketset_add (handle, NULL, newtkt);
  if (res != SHISHI_OK)
    {
      printf ("Could not add ticket: %s", shishi_strerror (res));
      return res;
    }

  if (!arg.silent)
    shishi_ticket_print (newtkt, stdout);

  if (!arg.silent)
    printf ("Adding new ticket...done\n");

  return SHISHI_OK;
}
