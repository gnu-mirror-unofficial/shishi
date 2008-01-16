/* safe.c --- Shishi SAFE self tests.
 * Copyright (C) 2002, 2003, 2007, 2008  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#include "utils.c"

void
test (Shishi * handle)
{
  Shishi_safe *safe;
  Shishi_key *key;
  Shishi_asn1 asn1safe;
  char *p, *q;
  size_t l, m;
  int32_t t;
  int res;

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
  free (p);

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
  free (q);

  /* shishi_safe_verify */
  res = shishi_safe_verify (safe, key);
  if (res == SHISHI_CRYPTO_ERROR)	/* t==42 unsupported cksumtype */
    success ("shishi_safe_verify() OK\n");
  else
    fail ("shishi_safe_verify() failed (%d)\n", res);

#if WITH_DES
  /* shishi_safe_set_cksum */
  res = shishi_safe_set_cksum (handle, asn1safe, SHISHI_RSA_MD5_DES,
			       "bar", 3);
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
#endif

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
  asn1safe = NULL;
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

  /* shishi_asn1_to_der() */
  res = shishi_asn1_to_der (handle, asn1safe, &q, &m);
  if (res == SHISHI_OK)
    success ("shishi_asn1_to_der() OK\n");
  else
    fail ("shishi_asn1_to_der() failed\n");

  /* Compare DER encodings of authenticators */
  if (l > 0 && m > 0 && l == m && memcmp (p, q, l) == 0)
    success ("DER comparison OK\n");
  else
    fail ("DER comparison failed\n");

  shishi_asn1_done (handle, asn1safe);
  free (q);
  free (p);

  /* unlink() */
  res = unlink ("safe.tmp");
  if (res == 0)
    success ("unlink() OK\n");
  else
    fail ("unlink() failed\n");
}
