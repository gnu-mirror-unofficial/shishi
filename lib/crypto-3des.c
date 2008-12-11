/* crypto-3des.c --- 3DES crypto functions.
 * Copyright (C) 2002, 2003, 2004, 2006, 2007, 2008  Simon Josefsson
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#include "internal.h"

/* Get prototypes. */
#include "crypto.h"

/* Get _shishi_escapeprint, etc. */
#include "utils.h"

static int
_des3_encrypt (Shishi * handle,
	       Shishi_key * key,
	       int keyusage,
	       const char *iv,
	       size_t ivlen,
	       char **ivout, size_t * ivoutlen,
	       const char *in, size_t inlen, char **out, size_t * outlen)
{
  return _shishi_simplified_encrypt (handle, key, keyusage, iv, ivlen, ivout,
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
  return _shishi_simplified_decrypt (handle, key, keyusage, iv, ivlen, ivout,
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

      res = _shishi_simplified_derivekey (handle, key, keyusage,
					  SHISHI_DERIVEKEYMODE_PRIVACY,
					  &derivedkey);
      if (res != SHISHI_OK)
	return res;

      res =
	_shishi_simplified_dencrypt (handle, derivedkey, iv, ivlen, ivout,
				     ivoutlen, in, inlen, out, outlen,
				     direction);

      shishi_key_done (derivedkey);

      if (res != SHISHI_OK)
	return res;
    }
  else
    {
      res =
	_shishi_simplified_dencrypt (handle, key, iv, ivlen, ivout, ivoutlen,
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

static void
des_set_odd_key_parity (char key[8])
{
  int i, j;

  for (i = 0; i < 8; i++)
    {
      int n_set_bits = 0;

      for (j = 1; j < 8; j++)
	if (key[i] & (1 << j))
	  n_set_bits++;

      key[i] &= ~1;
      if ((n_set_bits % 2) == 0)
	key[i] |= 1;
    }
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
		    const char *rnd, size_t rndlen, Shishi_key * outkey)
{
  char tmpkey[3 * 8];
  int i;

  if (rndlen < 168 / 8)
    return !SHISHI_OK;

  if (VERBOSECRYPTO (handle))
    {
      printf ("des3_random_to_key (random)\n");
      printf ("\t ;; random (length %d):\n", 168 / 8);
      _shishi_hexprint (rnd, 168 / 8);
      _shishi_binprint (rnd, 168 / 8);
    }

  memcpy (tmpkey, rnd, 7);
  memcpy (tmpkey + 8, rnd + 7, 7);
  memcpy (tmpkey + 16, rnd + 14, 7);
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
      _shishi_hexprint (tmpkey, 3 * 8);
      _shishi_binprint (tmpkey, 3 * 8);
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
      _shishi_escapeprint (string, stringlen);
      _shishi_hexprint (string, stringlen);
      printf ("\t ;; Salt:\n");
      _shishi_escapeprint (salt, saltlen);
      _shishi_hexprint (salt, saltlen);
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
  if (res == SHISHI_OK)
    /* key = DK (tmpKey, Constant) */
    res = shishi_dk (handle, key, SHISHI_DK_CONSTANT,
		     strlen (SHISHI_DK_CONSTANT), outkey);

  shishi_key_done (key);

  if (res != SHISHI_OK)
    return res;

  if (VERBOSECRYPTO (handle))
    {
      printf ("des3_string_to_key (string, salt)\n");
      printf ("\t ;; Key:\n");
      _shishi_hexprint (shishi_key_value (outkey),
			shishi_key_length (outkey));
      _shishi_binprint (shishi_key_value (outkey),
			shishi_key_length (outkey));
    }

  return SHISHI_OK;
}

static int
des3_checksum (Shishi * handle,
	       Shishi_key * key,
	       int keyusage,
	       int cksumtype,
	       const char *in, size_t inlen, char **out, size_t * outlen)
{
  return _shishi_simplified_checksum (handle, key, keyusage, cksumtype,
				      in, inlen, out, outlen);
}

cipherinfo des3_cbc_none_info = {
  SHISHI_DES3_CBC_NONE,
  "des3-cbc-none",
  8,
  8,
  3 * 8,
  3 * 8,
  SHISHI_HMAC_SHA1_DES3_KD,
  des3_random_to_key,
  des3_string_to_key,
  des3none_encrypt,
  des3none_decrypt
};

cipherinfo des3_cbc_sha1_kd_info = {
  SHISHI_DES3_CBC_HMAC_SHA1_KD,
  "des3-cbc-sha1-kd",
  8,
  8,
  3 * 8,
  3 * 8,
  SHISHI_HMAC_SHA1_DES3_KD,
  des3_random_to_key,
  des3_string_to_key,
  _des3_encrypt,
  _des3_decrypt
};

checksuminfo hmac_sha1_des3_kd_info = {
  SHISHI_HMAC_SHA1_DES3_KD,
  "hmac-sha1-des3-kd",
  20,
  des3_checksum,
  NULL
};
