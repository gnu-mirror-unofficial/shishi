/* crypto-aes.c		AES crypto functions
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
aes128_encrypt (Shishi * handle,
		Shishi_key * key,
		int keyusage,
		const char *iv, size_t ivlen,
		char **ivout, size_t * ivoutlen,
		const char *in, size_t inlen, char **out, size_t * outlen)
{
  return simplified_encrypt (handle, key, keyusage, iv, ivlen, ivout,
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
  return simplified_decrypt (handle, key, keyusage, iv, ivlen, ivout,
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
  return simplified_encrypt (handle, key, keyusage, iv, ivlen, ivout,
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
  return simplified_decrypt (handle, key, keyusage, iv, ivlen, ivout,
			     ivoutlen, in, inlen, out, outlen);
}

static int
aes_string_to_key (Shishi * handle,
		   const char *password,
		   size_t passwordlen,
		   const char *salt,
		   size_t saltlen, const char *parameter, Shishi_key * outkey)
{
  unsigned char key[256 / 8];
  int keylen = shishi_key_length (outkey);
  Shishi_key *tmpkey;
  int iterations = 0x0000b000;
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
      escapeprint (password, passwordlen);
      hexprint (password, passwordlen);
      printf ("\t ;; Salt:\n");
      escapeprint (salt, saltlen);
      hexprint (salt, saltlen);
      printf ("\t ;; Iteration count %d (%08x):\n", iterations, iterations);
    }

  /* tkey = random2key(PBKDF2(passphrase, salt, iter_count, keylength)) */
  res = shishi_pbkdf2_sha1 (handle, password, passwordlen, salt, saltlen,
			    iterations, keylen, key);
  if (res != SHISHI_OK)
    return res;

  res =
    shishi_key_from_value (handle, shishi_key_type (outkey), key, &tmpkey);
  if (res != SHISHI_OK)
    return res;

  /* key = DK(tkey, "kerberos") */
  res = shishi_dk (handle, tmpkey, "kerberos", strlen ("kerberos"), outkey);

  shishi_key_done (tmpkey);

  if (res != SHISHI_OK)
    return res;

  if (VERBOSECRYPTO (handle))
    {
      printf ("aes_string_to_key (password, salt)\n");
      printf ("\t ;; Key:\n");
      hexprint (shishi_key_value (outkey), shishi_key_length (outkey));
      binprint (shishi_key_value (outkey), shishi_key_length (outkey));
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
		      const char *random,
		      size_t randomlen, Shishi_key * outkey)
{
  if (randomlen < shishi_key_length (outkey))
    return SHISHI_CRYPTO_ERROR;

  shishi_key_value_set (outkey, random);

  return SHISHI_OK;
}

static int
aes256_random_to_key (Shishi * handle,
		      const char *random,
		      size_t randomlen, Shishi_key * outkey)
{
  if (randomlen < shishi_key_length (outkey))
    return SHISHI_CRYPTO_ERROR;

  shishi_key_value_set (outkey, random);

  return SHISHI_OK;
}

static int
aes128_checksum (Shishi * handle,
		 Shishi_key * key,
		 int keyusage,
		 int cksumtype,
		 const char *in, size_t inlen, char **out, size_t * outlen)
{
  return simplified_checksum (handle, key, keyusage, cksumtype,
			      in, inlen, out, outlen);
}

static int
aes256_checksum (Shishi * handle,
		 Shishi_key * key,
		 int keyusage,
		 int cksumtype,
		 const char *in, size_t inlen, char **out, size_t * outlen)
{
  return simplified_checksum (handle, key, keyusage, cksumtype,
			      in, inlen, out, outlen);
}
