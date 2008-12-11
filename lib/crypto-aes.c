/* crypto-aes.c --- AES crypto functions.
 * Copyright (C) 2002, 2003, 2004, 2005, 2007, 2008  Simon Josefsson
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
aes128_encrypt (Shishi * handle,
		Shishi_key * key,
		int keyusage,
		const char *iv, size_t ivlen,
		char **ivout, size_t * ivoutlen,
		const char *in, size_t inlen, char **out, size_t * outlen)
{
  return _shishi_simplified_encrypt (handle, key, keyusage, iv, ivlen, ivout,
				     ivoutlen, in, inlen, out, outlen);
}

static int
aes128_decrypt (Shishi * handle,
		Shishi_key * key,
		int keyusage,
		const char *iv, size_t ivlen,
		char **ivout, size_t * ivoutlen,
		const char *in, size_t inlen, char **out, size_t * outlen)
{
  return _shishi_simplified_decrypt (handle, key, keyusage, iv, ivlen, ivout,
				     ivoutlen, in, inlen, out, outlen);
}

static int
aes256_encrypt (Shishi * handle,
		Shishi_key * key,
		int keyusage,
		const char *iv, size_t ivlen,
		char **ivout, size_t * ivoutlen,
		const char *in, size_t inlen, char **out, size_t * outlen)
{
  return _shishi_simplified_encrypt (handle, key, keyusage, iv, ivlen, ivout,
				     ivoutlen, in, inlen, out, outlen);
}

static int
aes256_decrypt (Shishi * handle,
		Shishi_key * key,
		int keyusage,
		const char *iv, size_t ivlen,
		char **ivout, size_t * ivoutlen,
		const char *in, size_t inlen, char **out, size_t * outlen)
{
  return _shishi_simplified_decrypt (handle, key, keyusage, iv, ivlen, ivout,
				     ivoutlen, in, inlen, out, outlen);
}

static int
aes_string_to_key (Shishi * handle,
		   const char *password,
		   size_t passwordlen,
		   const char *salt,
		   size_t saltlen, const char *parameter, Shishi_key * outkey)
{
  char key[256 / 8];
  int keylen = shishi_key_length (outkey);
  Shishi_key *tmpkey;
  int iterations = 0x00001000;
  int res;

  if (parameter)
    {
      iterations = (parameter[0] & 0xFF) << 24;
      iterations |= (parameter[1] & 0xFF) << 16;
      iterations |= (parameter[2] & 0xFF) << 8;
      iterations |= parameter[3] & 0xFF;
    }

  if (VERBOSECRYPTO (handle))
    {
      printf ("aes_string_to_key (password, salt)\n");
      printf ("\t ;; Password:\n");
      _shishi_escapeprint (password, passwordlen);
      _shishi_hexprint (password, passwordlen);
      printf ("\t ;; Salt:\n");
      _shishi_escapeprint (salt, saltlen);
      _shishi_hexprint (salt, saltlen);
      printf ("\t ;; Iteration count %d (%08x):\n", iterations, iterations);
    }

  /* tkey = random2key(PBKDF2(passphrase, salt, iter_count, keylength)) */
  res = shishi_pbkdf2_sha1 (handle, password, passwordlen, salt, saltlen,
			    iterations, keylen, key);
  if (res != SHISHI_OK)
    return res;

  res = shishi_key_from_value (handle, shishi_key_type (outkey),
			       key, &tmpkey);
  if (res != SHISHI_OK)
    return res;

  /* key = DK(tkey, Constant) */
  res = shishi_dk (handle, tmpkey, SHISHI_DK_CONSTANT,
		   strlen (SHISHI_DK_CONSTANT), outkey);

  shishi_key_done (tmpkey);

  if (res != SHISHI_OK)
    return res;

  if (VERBOSECRYPTO (handle))
    {
      printf ("aes_string_to_key (password, salt)\n");
      printf ("\t ;; Key:\n");
      _shishi_hexprint (shishi_key_value (outkey),
			shishi_key_length (outkey));
      _shishi_binprint (shishi_key_value (outkey),
			shishi_key_length (outkey));
    }

  return SHISHI_OK;
}

static int
aes128_string_to_key (Shishi * handle,
		      const char *password,
		      size_t passwordlen,
		      const char *salt,
		      size_t saltlen,
		      const char *parameter, Shishi_key * outkey)
{
  return aes_string_to_key (handle, password, passwordlen,
			    salt, saltlen, parameter, outkey);
}

static int
aes256_string_to_key (Shishi * handle,
		      const char *password,
		      size_t passwordlen,
		      const char *salt,
		      size_t saltlen,
		      const char *parameter, Shishi_key * outkey)
{
  return aes_string_to_key (handle, password, passwordlen,
			    salt, saltlen, parameter, outkey);
}

static int
aes128_random_to_key (Shishi * handle,
		      const char *rnd, size_t rndlen, Shishi_key * outkey)
{
  if (rndlen < shishi_key_length (outkey))
    return SHISHI_CRYPTO_ERROR;

  shishi_key_value_set (outkey, rnd);

  return SHISHI_OK;
}

static int
aes256_random_to_key (Shishi * handle,
		      const char *rnd, size_t rndlen, Shishi_key * outkey)
{
  if (rndlen < shishi_key_length (outkey))
    return SHISHI_CRYPTO_ERROR;

  shishi_key_value_set (outkey, rnd);

  return SHISHI_OK;
}

static int
aes128_checksum (Shishi * handle,
		 Shishi_key * key,
		 int keyusage,
		 int cksumtype,
		 const char *in, size_t inlen, char **out, size_t * outlen)
{
  return _shishi_simplified_checksum (handle, key, keyusage, cksumtype,
				      in, inlen, out, outlen);
}

static int
aes256_checksum (Shishi * handle,
		 Shishi_key * key,
		 int keyusage,
		 int cksumtype,
		 const char *in, size_t inlen, char **out, size_t * outlen)
{
  return _shishi_simplified_checksum (handle, key, keyusage, cksumtype,
				      in, inlen, out, outlen);
}

cipherinfo aes128_cts_hmac_sha1_96_info = {
  SHISHI_AES128_CTS_HMAC_SHA1_96,
  "aes128-cts-hmac-sha1-96",
  16,
  16,
  128 / 8,
  128 / 8,
  SHISHI_HMAC_SHA1_96_AES128,
  aes128_random_to_key,
  aes128_string_to_key,
  aes128_encrypt,
  aes128_decrypt
};

cipherinfo aes256_cts_hmac_sha1_96_info = {
  SHISHI_AES256_CTS_HMAC_SHA1_96,
  "aes256-cts-hmac-sha1-96",
  16,
  16,
  256 / 8,
  256 / 8,
  SHISHI_HMAC_SHA1_96_AES256,
  aes256_random_to_key,
  aes256_string_to_key,
  aes256_encrypt,
  aes256_decrypt
};

checksuminfo hmac_sha1_96_aes128_info = {
  SHISHI_HMAC_SHA1_96_AES128,
  "hmac-sha1-96-aes128",
  96 / 8,
  aes128_checksum,
  NULL
};

checksuminfo hmac_sha1_96_aes256_info = {
  SHISHI_HMAC_SHA1_96_AES256,
  "hmac-sha1-96-aes256",
  96 / 8,
  aes256_checksum,
  NULL
};
