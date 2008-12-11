/* server.c --- Sample server with authentication using Shishi.
 * Copyright (C) 2003, 2004, 2007, 2008  Simon Josefsson
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include <shishi.h>

#define SERVICE "sample"

/* XXX remove this */
const char *program_name = "client";

static int
doit (Shishi * h, Shishi_ap * ap, int verbose)
{
  Shishi_asn1 asn1safe;
  Shishi_safe *safe;
  char *userdata;
  size_t userdatalen;
  int res;

  printf ("Application exchange start.  Press ^D to finish.\n");

  while ((res = shishi_safe_parse (h, stdin, &asn1safe)) == SHISHI_OK)
    {
      if (res != SHISHI_OK)
	{
	  fprintf (stderr, "Could not read SAFE:\n%s\n%s\n",
		   shishi_strerror (res), shishi_error (h));
	  return 1;
	}

      res = shishi_safe (h, &safe);
      if (res != SHISHI_OK)
	{
	  fprintf (stderr, "Could not create SAFE:\n%s\n%s\n",
		   shishi_strerror (res), shishi_error (h));
	  return 1;
	}

      shishi_safe_safe_set (safe, asn1safe);

      res = shishi_safe_verify (safe, shishi_ap_key (ap));
      if (res != SHISHI_OK)
	{
	  fprintf (stderr, "Could not verify SAFE:\n%s\n%s\n",
		   shishi_strerror (res), shishi_error (h));
	  return 1;
	}

      printf ("Verified SAFE successfully...\n");

      res = shishi_safe_user_data (h, asn1safe, &userdata, &userdatalen);
      if (res != SHISHI_OK)
	{
	  fprintf (stderr, "Could not extract user data:\n%s\n%s\n",
		   shishi_strerror (res), shishi_error (h));
	  return 1;
	}
      userdata[userdatalen] = '\0';
      printf ("user data: `%s'\n", userdata);

    }

  if (ferror (stdin))
    {
      printf ("error reading stdin\n");
      return 1;
    }

  return 0;
}

static Shishi_ap *
auth (Shishi * h, int verbose, const char *cname, const char *sname)
{
  Shishi_key *key;
  Shishi_ap *ap;
  Shishi_asn1 apreq;
  char *buf;
  size_t buflen;
  int rc;

  printf ("Client: %s\n", cname);
  printf ("Server: %s\n", sname);

  /* Get key for the server. */

  key = shishi_hostkeys_for_server (h, sname);
  if (!key)
    {
      printf ("could not find key: %s\n", shishi_error (h));
      return NULL;
    }

  if (verbose)
    shishi_key_print (h, stderr, key);

  /* Read Authentication request from client */

  printf ("Waiting for client to authenticate itself...\n");

  rc = shishi_apreq_parse (h, stdin, &apreq);
  if (rc != SHISHI_OK)
    {
      printf ("could not read AP-REQ: %s\n", shishi_strerror (rc));
      return NULL;
    }

  /* Create Authentication context */

  rc = shishi_ap (h, &ap);
  if (rc != SHISHI_OK)
    {
      printf ("Could not create AP: %s\n", shishi_strerror (rc));
      return NULL;
    }

  /* Store request in context */

  shishi_ap_req_set (ap, apreq);

  /* Process authentication request */

  rc = shishi_ap_req_process (ap, key);
  if (rc != SHISHI_OK)
    {
      printf ("Could not process AP-REQ: %s\n", shishi_strerror (rc));
      return NULL;
    }

  if (verbose)
    shishi_authenticator_print (h, stderr, shishi_ap_authenticator (ap));

  rc = shishi_authenticator_client (h, shishi_ap_authenticator (ap),
				    &buf, &buflen);
  printf ("Client name (from authenticator): %.*s\n", buflen, buf);
  free (buf);

  rc = shishi_encticketpart_clientrealm
    (h, shishi_tkt_encticketpart (shishi_ap_tkt (ap)), &buf, &buflen);
  printf ("Client name (from encticketpart): %.*s\n", buflen, buf);
  free (buf);

  rc = shishi_ticket_server (h, shishi_tkt_ticket (shishi_ap_tkt (ap)),
			     &buf, &buflen);
  printf ("Server name (from ticket): %.*s\n", buflen, buf);
  free (buf);

  /* User is authenticated. */

  printf ("User authenticated.\n");

  /* Authenticate ourself to client, if request */

  if (shishi_apreq_mutual_required_p (h, apreq))
    {
      Shishi_asn1 aprep;

      printf ("Mutual authentication required.\n");

      rc = shishi_ap_rep_asn1 (ap, &aprep);
      if (rc != SHISHI_OK)
	{
	  printf ("Error creating AP-REP: %s\n", shishi_strerror (rc));
	  return NULL;
	}

      if (verbose)
	shishi_encapreppart_print (h, stderr, shishi_ap_encapreppart (ap));

      shishi_aprep_print (h, stdout, aprep);

      /* We are authenticated to client */
    }

  return ap;
}

int
main (int argc, char *argv[])
{
  Shishi *h;
  Shishi_ap *ap;
  char *sname;
  int rc;

  printf ("sample-server (shishi " SHISHI_VERSION ")\n");

  if (!shishi_check_version (SHISHI_VERSION))
    {
      printf ("shishi_check_version() failed:\n"
	      "Header file incompatible with shared library.\n");
      return 1;
    }

  rc = shishi_init_server (&h);
  if (rc != SHISHI_OK)
    {
      printf ("error initializing shishi: %s\n", shishi_strerror (rc));
      return 1;
    }

  if (argc > 1)
    sname = argv[1];
  else
    sname = shishi_server_for_local_service (h, SERVICE);

  ap = auth (h, 1, shishi_principal_default (h), sname);

  if (ap)
    rc = doit (h, ap, 1);
  else
    rc = 1;

  shishi_done (h);

  return rc;
}
