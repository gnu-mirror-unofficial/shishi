/* crypto-3des.c	3DES crypto functions
 * Copyright (C) 2002, 2003  Simon Josefsson
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
 * Note: This file is #include'd by crypto.c.
 *
 */

static int
_des3_encrypt (Shishi * handle,
	       Shishi_key * key,
	       int keyusage,
	       const char *iv,
	       size_t ivlen,
	       char **ivout, size_t * ivoutlen,
	       const char *in, size_t inlen, char **out, size_t * outlen)
{
  return simplified_encrypt (handle, key, keyusage, iv, ivlen, ivout,
			     ivoutlen, in, inlen, out, outlen);
}

static int
_des3_decrypt (Shishi * handle,
	       Shishi_key * key,
	       int keyusage,
	       const char *iv,
	       size_t ivlen,
	       char **ivout, size_t * ivoutlen,
	       const char *in, size_t inlen, char **out, size_t * outlen)
{
  return simplified_decrypt (handle, key, keyusage, iv, ivlen, ivout,
			     ivoutlen, in, inlen, out, outlen);
}

static int
des3none_dencrypt (Shishi * handle,
		   Shishi_key * key,
		   int keyusage,
		   const char *iv, size_t ivlen,
		   char **ivout, size_t * ivoutlen,
		   const char *in, size_t inlen,
		   char **out, size_t * outlen, int direction)
{
  int res;

  if (keyusage != 0)
    {
      Shishi_key *derivedkey;

      res = simplified_derivekey (handle, key, keyusage,
				  SHISHI_DERIVEKEYMODE_PRIVACY, &derivedkey);
      if (res != SHISHI_OK)
	return res;

      res =
	simplified_dencrypt (handle, derivedkey, iv, ivlen, ivout, ivoutlen,
			     in, inlen, out, outlen, direction);

      shishi_key_done (derivedkey);

      if (res != SHISHI_OK)
	return res;
    }
  else
    {
      res = simplified_dencrypt (handle, key, iv, ivlen, ivout, ivoutlen,
				 in, inlen, out, outlen, direction);
      if (res != SHISHI_OK)
	return res;
    }

  return SHISHI_OK;
}

static int
des3none_encrypt (Shishi * handle,
		  Shishi_key * key,
		  int keyusage,
		  const char *iv, size_t ivlen,
		  char **ivout, size_t * ivoutlen,
		  const char *in, size_t inlen, char **out, size_t * outlen)
{
  return des3none_dencrypt (handle, key, keyusage, iv, ivlen, ivout, ivoutlen,
			    in, inlen, out, outlen, 0);
}

static int
des3none_decrypt (Shishi * handle,
		  Shishi_key * key,
		  int keyusage,
		  const char *iv, size_t ivlen,
		  char **ivout, size_t * ivoutlen,
		  const char *in, size_t inlen, char **out, size_t * outlen)
{
  return des3none_dencrypt (handle, key, keyusage, iv, ivlen, ivout, ivoutlen,
			    in, inlen, out, outlen, 1);
}

/* The 168 bits of random key data are converted to a protocol key
 * value as follows.  First, the 168 bits are divided into three
 * groups of 56 bits, which are expanded individually into 64 bits as
 * follows:
 *
 *          1  2  3  4  5  6  7  p
 *          9 10 11 12 13 14 15  p
 *         17 18 19 20 21 22 23  p
 *         25 26 27 28 29 30 31  p
 *         33 34 35 36 37 38 39  p
 *         41 42 43 44 45 46 47  p
 *         49 50 51 52 53 54 55  p
 *         56 48 40 32 24 16  8  p
 *
 * The "p" bits are parity bits computed over the data bits.  The
 * output of the three expansions are concatenated to form the
 * protocol key value.
 *
 */
static int
des3_random_to_key (Shishi * handle,
		    const char *random, size_t randomlen, Shishi_key * outkey)
{
  unsigned char tmpkey[3 * 8];
  int i;

  if (randomlen < 168 / 8)
    return !SHISHI_OK;

  if (VERBOSECRYPTO (handle))
    {
      printf ("des3_random_to_key (random)\n");
      printf ("\t ;; random (length %d):\n", 168 / 8);
      hexprint (random, 168 / 8);
      puts ("");
      binprint (random, 168 / 8);
      puts ("");
    }

  memcpy (tmpkey, random, 7);
  memcpy (tmpkey + 8, random + 7, 7);
  memcpy (tmpkey + 16, random + 14, 7);
  for (i = 0; i < 3; i++)
    {
      tmpkey[i * 8 + 7] =
	((tmpkey[i * 8 + 0] & 0x01) << 1) |
	((tmpkey[i * 8 + 1] & 0x01) << 2) |
	((tmpkey[i * 8 + 2] & 0x01) << 3) |
	((tmpkey[i * 8 + 3] & 0x01) << 4) |
	((tmpkey[i * 8 + 4] & 0x01) << 5) |
	((tmpkey[i * 8 + 5] & 0x01) << 6) | ((tmpkey[i * 8 + 6] & 0x01) << 7);
      des_set_odd_key_parity (tmpkey + i * 8);
    }

  shishi_key_value_set (outkey, tmpkey);

  if (VERBOSECRYPTO (handle))
    {
      printf ("key = des3_random_to_key (random)\n");
      printf ("\t ;; key:\n");
      hexprint (tmpkey, 3 * 8);
      puts ("");
      binprint (tmpkey, 3 * 8);
      puts ("");
    }

  return SHISHI_OK;
}

static int
des3_string_to_key (Shishi * handle,
		    const char *string,
		    size_t stringlen,
		    const char *salt,
		    size_t saltlen,
		    const char *parameter, Shishi_key * outkey)
{
  char *s;
  int n_s;
  Shishi_key *key;
  char nfold[168 / 8];
  int nfoldlen = 168 / 8;
  int res;

  if (VERBOSECRYPTO (handle))
    {
      printf ("des3_string_to_key (string, salt)\n");
      printf ("\t ;; String:\n");
      escapeprint (string, stringlen);
      hexprint (string, stringlen);
      puts ("");
      printf ("\t ;; Salt:\n");
      escapeprint (salt, saltlen);
      hexprint (salt, saltlen);
      puts ("");
    }

  /* s = passwordString + salt */
  n_s = stringlen + saltlen;
  s = (char *) xmalloc (n_s);
  memcpy (s, string, stringlen);
  memcpy (s + stringlen, salt, saltlen);

  /* tmpKey = random-to-key(168-fold(s)) */
  res = shishi_n_fold (handle, s, n_s, nfold, nfoldlen);
  free (s);
  if (res != SHISHI_OK)
    return res;

  res = shishi_key_from_value (handle, shishi_key_type (outkey), NULL, &key);
  if (res != SHISHI_OK)
    return res;

  res = des3_random_to_key (handle, nfold, nfoldlen, key);
  if (res != SHISHI_OK)
    return res;

  /* key = DK (tmpKey, KerberosConstant) */
  res = shishi_dk (handle, key, "kerberos", strlen ("kerberos"), outkey);
  if (res != SHISHI_OK)
    return res;

  shishi_key_done (key);

  if (VERBOSECRYPTO (handle))
    {
      printf ("des3_string_to_key (string, salt)\n");
      printf ("\t ;; Key:\n");
      hexprint (shishi_key_value (outkey), shishi_key_length (outkey));
      binprint (shishi_key_value (outkey), shishi_key_length (outkey));
      puts ("");
    }

  return SHISHI_OK;
}

static int
des3_checksum (Shishi * handle,
	       Shishi_key * key,
	       int keyusage,
	       int cksumtype,
	       char *in, size_t inlen, char **out, size_t * outlen)
{
  return simplified_checksum (handle, key, keyusage, cksumtype,
			      in, inlen, out, outlen);
}
