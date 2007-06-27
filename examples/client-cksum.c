/* client-cksum.c --- Sample Shishi authenticated client, with checksum data.
 * Copyright (C) 2003, 2004, 2007  Simon Josefsson
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
#include <string.h>

#include <shishi.h>

#define SERVICE "sample"

/* XXX remove this */
const char *program_name = "client";

static int
doit (Shishi * handle, Shishi_ap * ap, int verbose)
{
  char line[BUFSIZ];

#if 0
  /* XXX Unfinished application-level security */
  res = shishi_safe (handle, &safe);
  if (res != SHISHI_OK)
    {
      printf ("Could not build SAFE: %s\n", shishi_strerror (res));
      return res;
    }

  res = shishi_safe_set_user_data (handle, shishi_safe_safe (safe), "foo", 0);
  if (res != SHISHI_OK)
    {
      printf ("Could not set application data in SAFE: %s\n",
	      shishi_strerror (res));
      return res;
    }

  res = shishi_safe_build (safe, key);
  if (res != SHISHI_OK)
    {
      printf ("Could not build SAFE: %s\n", shishi_strerror (res));
      return res;
    }

  res = shishi_safe_print (handle, stdout, shishi_safe_safe (safe));
  if (res != SHISHI_OK)
    {
      printf ("Could not print SAFE: %s\n", shishi_strerror (res));
      return res;
    }
#endif

  printf ("Application exchange start.  Press ^D to finish.\n");

  while (fgets (line, sizeof (line), stdin))
    {
      printf ("read: %s", line);
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
  Shishi_ap *ap;
  Shishi_tkt *tkt;
  Shishi_tkts_hint hint;
  int rc;

  printf ("Client: %s\n", cname);
  printf ("Server: %s\n", sname);

  /* Get a ticket for the server. */

  memset (&hint, 0, sizeof (hint));
  hint.client = (char *) cname;
  hint.server = (char *) sname;
  tkt = shishi_tkts_get (shishi_tkts_default (h), &hint);
  if (!tkt)
    {
      printf ("cannot find ticket for \"%s\"\n", sname);
      return NULL;
    }

  if (verbose)
    shishi_tkt_pretty_print (tkt, stderr);

  /* Create Authentication context */

  rc = shishi_ap_tktoptions (h, &ap, tkt, SHISHI_APOPTIONS_MUTUAL_REQUIRED);
  if (rc != SHISHI_OK)
    {
      printf ("cannot create authentication context\n");
      return NULL;
    }

  /* Add checksum of some application data to the AP.
   *
   * Note that only a pointer to this memory area is stored in the AP,
   * so you MUST keep it allocated, at least until
   * shishi_ap_req_build(ap) is finished.  This might be changed in
   * the future, probably by copying the data into the AP.
   */

  shishi_ap_authenticator_cksumdata_set (ap, "attack at dawn",
					 strlen ("attack at dawn"));

  /* Build Authentication request */

  rc = shishi_ap_req_build (ap);
  if (rc != SHISHI_OK)
    {
      printf ("cannot build authentication request: %s\n",
	      shishi_strerror (rc));
      return NULL;
    }

  if (verbose)
    shishi_authenticator_print (h, stderr, shishi_ap_authenticator (ap));

  /* Authentication ourself to server */

  shishi_apreq_print (h, stdout, shishi_ap_req (ap));
  /* Note: to get the binary blob to send, use:
   *
   * char *out; int outlen;
   * ...
   * rc = shishi_ap_req_der (ap, &out, &outlen);
   * ...
   * write(fd, out, outlen);
   */

  /* For mutual authentication, wait for server reply. */

  if (shishi_apreq_mutual_required_p (h, shishi_ap_req (ap)))
    {
      Shishi_asn1 aprep;

      printf ("Waiting for server to authenticate itself...\n");

      rc = shishi_aprep_parse (h, stdin, &aprep);
      if (rc != SHISHI_OK)
	{
	  printf ("Cannot parse AP-REP from server: %s\n",
		  shishi_strerror (rc));
	  return NULL;
	}

      rc = shishi_ap_rep_verify_asn1 (ap, aprep);
      if (rc == SHISHI_OK)
	printf ("AP-REP verification OK...\n");
      else
	{
	  if (rc == SHISHI_APREP_VERIFY_FAILED)
	    printf ("AP-REP verification failed...\n");
	  else
	    printf ("AP-REP verification error: %s\n", shishi_strerror (rc));
	  return NULL;
	}

      /* The server is authenticated. */
      printf ("Server authenticated.\n");
    }

  /* We are now authenticated. */
  printf ("User authenticated.\n");

  return ap;
}

int
main (int argc, char *argv[])
{
  Shishi *h;
  Shishi_ap *ap;
  char *sname;
  int rc;

  printf ("sample-client (shishi " SHISHI_VERSION ")\n");

  if (!shishi_check_version (SHISHI_VERSION))
    {
      printf ("shishi_check_version() failed:\n"
	      "Header file incompatible with shared library.\n");
      return 1;
    }

  rc = shishi_init (&h);
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
