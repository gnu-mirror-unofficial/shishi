/* priv.c --- Shishi PRIV self tests.
 * Copyright (C) 2002, 2003, 2006, 2007  Simon Josefsson
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
  Shishi_priv *priv;
  Shishi_key *key;
  Shishi_asn1 asn1priv;
  Shishi_asn1 asn1encprivpart;
  char *p, *q;
  size_t l, m;
  int32_t t;
  int res;

  if (debug)
    shishi_cfg (handle, strdup ("verbose-crypto"));

  /* shishi_priv() */
  res = shishi_priv (handle, &priv);
  if (debug)
    printf ("shishi_priv () => `%p'.\n", priv);
  if (res == SHISHI_OK)
    success ("shishi_priv() OK\n");
  else
    fail ("shishi_priv() failed\n");

  /* shishi_priv_key */
  key = shishi_priv_key (priv);
  if (key)
    success ("shishi_priv_key() OK\n");
  else
    fail ("shishi_priv_key() failed\n");

  /* shishi_priv_priv */
  asn1priv = shishi_priv_priv (priv);
  if (asn1priv)
    success ("shishi_priv_priv() OK\n");
  else
    fail ("shishi_priv_priv() failed\n");

  /* shishi_priv_encprivpart */
  asn1encprivpart = shishi_priv_encprivpart (priv);
  if (asn1encprivpart)
    success ("shishi_priv_encprivpart() OK\n");
  else
    fail ("shishi_priv_encprivpart() failed\n");

  /* shishi_encprivpart_set_user_data */
  res = shishi_encprivpart_set_user_data (handle, asn1encprivpart, "foo", 3);
  if (res == SHISHI_OK)
    success ("shishi_encprivpart_set_user_data() OK\n");
  else
    fail ("shishi_encprivpart_set_user_data() failed (%d)\n", res);

  /* shishi_encprivpart_user_data */
  res = shishi_encprivpart_user_data (handle, asn1encprivpart, &p, &l);
  if (debug)
    escapeprint (p, l);
  if (res == SHISHI_OK && l == 3 && memcmp (p, "foo", 3) == 0)
    success ("shishi_encprivpart_user_data() OK\n");
  else
    fail ("shishi_encprivpart_user_data() failed (%d)\n", res);
  free (p);

  /* shishi_priv_set_cksum */
  res = shishi_priv_set_enc_part (handle, asn1priv, 42, "bar", 3);
  if (res == SHISHI_OK)
    success ("shishi_priv_set_enc_part() OK\n");
  else
    fail ("shishi_priv_set_enc_part() failed (%d)\n", res);

  /* shishi_priv_enc_part_etype */
  res = shishi_priv_enc_part_etype (handle, asn1priv, &t);
  if (debug)
    printf ("type=%d\n", t);
  if (res == SHISHI_OK && t == 42)
    success ("shishi_priv_enc_part_etype() OK\n");
  else
    fail ("shishi_priv_enc_part_etype() failed (%d)\n", res);

  /* shishi_priv_process */
  res = shishi_priv_process (priv, key);
  if (res == SHISHI_PRIV_BAD_KEYTYPE)	/* t==42 unsupported etype */
    success ("shishi_priv_proces() OK\n");
  else
    fail ("shishi_priv_process() failed (%d)\n", res);

  /* shishi_priv_priv_der() */
  res = shishi_priv_priv_der (priv, &p, &l);
  if (res == SHISHI_OK)
    success ("shishi_priv_priv_der() OK\n");
  else
    fail ("shishi_priv_priv_der() failed\n");

  /* shishi_priv_to_file() */
  res = shishi_priv_to_file (handle, asn1priv, SHISHI_FILETYPE_TEXT,
			     "priv.tmp");
  if (res == SHISHI_OK)
    success ("shishi_priv_to_file() OK\n");
  else
    fail ("shishi_priv_to_file() failed\n");

  /* shishi_priv_done() */
  shishi_priv_done (priv);
  success ("shishi_priv_done() OK\n");

  /* shishi_authenticator_from_file() */
  asn1priv = NULL;
  res = shishi_priv_from_file (handle, &asn1priv, SHISHI_FILETYPE_TEXT,
			       "priv.tmp");
  if (res == SHISHI_OK)
    success ("shishi_priv_from_file() OK\n");
  else
    fail ("shishi_priv_from_file() failed\n");

  if (debug)
    {
      /* shishi_priv_print() */
      res = shishi_priv_print (handle, stdout, asn1priv);
      if (res == SHISHI_OK)
	success ("shishi_priv_print() OK\n");
      else
	fail ("shishi_priv_print() failed\n");
    }

  /* shishi_asn1_to_der() */
  res = shishi_asn1_to_der (handle, asn1priv, &q, &m);
  if (res == SHISHI_OK)
    success ("shishi_asn1_to_der() OK\n");
  else
    fail ("shishi_asn1_to_der() failed\n");

  shishi_asn1_done (handle, asn1priv);

  /* Compare DER encodings of authenticators */
  if (l > 0 && m > 0 && l == m && memcmp (p, q, l) == 0)
    success ("DER comparison OK\n");
  else
    fail ("DER comparison failed\n");

  free (q);
  free (p);

  /* unlink() */
  res = unlink ("priv.tmp");
  if (res == 0)
    success ("unlink() OK\n");
  else
    fail ("unlink() failed\n");
}
