/* safe.c	Shishi SAFE self tests.
 * Copyright (C) 2002, 2003  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with Shishi; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "utils.c"
#include <shishi.h>

int
main (int argc, char *argv[])
{
  Shishi *handle;
  Shishi_safe *safe;
  Shishi_key *key;
  Shishi_asn1 asn1safe;
  char *p, *q;
  size_t l, m;
  int32_t t;
  char buffer[BUFSIZ];
  char buffer2[BUFSIZ];
  int res;

  do
    if (strcmp (argv[argc - 1], "-v") == 0 ||
	strcmp (argv[argc - 1], "--verbose") == 0)
      verbose = 1;
    else if (strcmp (argv[argc - 1], "-d") == 0 ||
	     strcmp (argv[argc - 1], "--debug") == 0)
      debug = 1;
    else if (strcmp (argv[argc - 1], "-b") == 0 ||
	     strcmp (argv[argc - 1], "--break-on-error") == 0)
      break_on_error = 1;
    else if (strcmp (argv[argc - 1], "-h") == 0 ||
	     strcmp (argv[argc - 1], "-?") == 0 ||
	     strcmp (argv[argc - 1], "--help") == 0)
      {
	printf ("Usage: %s [-vdbh?] [--verbose] [--debug] "
		"[--break-on-error] [--help]\n", argv[0]);
	return 1;
      }
  while (argc-- > 1);

  handle = shishi ();
  if (handle == NULL)
    {
      fail ("Could not initialize shishi\n");
      return 1;
    }

  if (debug)
    shishi_cfg (handle, strdup ("verbose"));

  escapeprint (NULL, 0);
  hexprint (NULL, 0);
  binprint (NULL, 0);

  /* shishi_safe() */
  res = shishi_safe (handle, &safe);
  if (debug)
    printf ("shishi_safe () => `%p'.\n", safe);
  if (res == SHISHI_OK)
    success ("shishi_safe() OK\n");
  else
    fail ("shishi_safe() failed\n");

  /* shishi_safe_key */
  key = shishi_safe_key (safe);
  if (key)
    success ("shishi_safe_key() OK\n");
  else
    fail ("shishi_safe_key() failed\n");

  /* shishi_safe_safe */
  asn1safe = shishi_safe_safe (safe);
  if (asn1safe)
    success ("shishi_safe_safe() OK\n");
  else
    fail ("shishi_safe_safe() failed\n");

  /* shishi_safe_set_user_data */
  res = shishi_safe_set_user_data (handle, asn1safe, "foo", 3);
  if (res == SHISHI_OK)
    success ("shishi_safe_set_user_data() OK\n");
  else
    fail ("shishi_safe_set_user_data() failed (%d)\n", res);

  /* shishi_safe_user_data */
  res = shishi_safe_user_data (handle, asn1safe, &p, &l);
  if (debug)
    escapeprint (p, l);
  if (res == SHISHI_OK && l == 3 && memcmp (p, "foo", 3) == 0)
    success ("shishi_safe_user_data() OK\n");
  else
    fail ("shishi_safe_user_data() failed (%d)\n", res);

  /* shishi_safe_set_cksum */
  res = shishi_safe_set_cksum (handle, asn1safe, 42, "bar", 3);
  if (res == SHISHI_OK)
    success ("shishi_safe_set_cksum() OK\n");
  else
    fail ("shishi_safe_set_cksum() failed (%d)\n", res);

  /* shishi_safe_cksum */
  res = shishi_safe_cksum (handle, asn1safe, &t, &q, &m);
  if (debug)
    {
      printf ("type=%d\n", t);
      escapeprint (q, m);
    }
  if (res == SHISHI_OK && t == 42 && m == 3 && memcmp (q, "bar", 3) == 0)
    success ("shishi_safe_cksum() OK\n");
  else
    fail ("shishi_safe_cksum() failed (%d)\n", res);

  /* shishi_safe_verify */
  res = shishi_safe_verify (safe, key);
  if (res == SHISHI_CRYPTO_ERROR) /* t==42 unsupported cksumtype */
    success ("shishi_safe_verify() OK\n");
  else
    fail ("shishi_safe_verify() failed (%d)\n", res);

  /* shishi_safe_set_cksum */
  res = shishi_safe_set_cksum (handle, asn1safe, SHISHI_RSA_MD5_DES, "bar", 3);
  if (res == SHISHI_OK)
    success ("shishi_safe_set_cksum() OK\n");
  else
    fail ("shishi_safe_set_cksum() failed (%d)\n", res);

  /* shishi_safe_verify */
  res = shishi_safe_verify (safe, key);
  if (res == SHISHI_VERIFY_FAILED)
    success ("shishi_safe_verify() OK\n");
  else
    fail ("shishi_safe_verify() failed (%d)\n", res);

  /* shishi_safe_safe_der() */
  res = shishi_safe_safe_der (safe, &p, &l);
  if (res == SHISHI_OK)
    success ("shishi_safe_safe_der() OK\n");
  else
    fail ("shishi_safe_safe_der() failed\n");

  /* shishi_safe_to_file() */
  res = shishi_safe_to_file (handle, asn1safe, SHISHI_FILETYPE_TEXT,
			     "safe.tmp");
  if (res == SHISHI_OK)
    success ("shishi_safe_to_file() OK\n");
  else
    fail ("shishi_safe_to_file() failed\n");

  /* shishi_safe_done() */
  shishi_safe_done (safe);
  success ("shishi_safe_done() OK\n");

  /* shishi_authenticator_from_file() */
  res = shishi_safe_from_file (handle, &asn1safe, SHISHI_FILETYPE_TEXT,
			       "safe.tmp");
  if (res == SHISHI_OK)
    success ("shishi_safe_from_file() OK\n");
  else
    fail ("shishi_safe_from_file() failed\n");

  if (debug)
    {
      /* shishi_safe_print() */
      res = shishi_safe_print (handle, stdout, asn1safe);
      if (res == SHISHI_OK)
	success ("shishi_safe_print() OK\n");
      else
	fail ("shishi_safe_print() failed\n");
    }

  /* shishi_a2d() */
  m = sizeof (buffer2);
  res = shishi_a2d (handle, asn1safe, buffer2, &m);
  if (res == SHISHI_OK)
    success ("shishi_a2d() OK\n");
  else
    fail ("shishi_a2d() failed\n");

  /* Compare DER encodings of authenticators */
  if (l > 0 && m > 0 && l == m && memcmp (p, buffer2, l) == 0)
    success ("DER comparison OK\n");
  else
    fail ("DER comparison failed\n");

  /* unlink() */
  res = unlink ("safe.tmp");
  if (res == 0)
    success ("unlink() OK\n");
  else
    fail ("unlink() failed\n");

  shishi_done (handle);

  if (verbose)
    printf ("SAFE self tests done with %d errors\n", error_count);

  return error_count ? 1 : 0;
}
