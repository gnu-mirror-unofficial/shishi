/* crypto-aes.c		AES crypto functions
 * Copyright (C) 2002  Simon Josefsson
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
 * Note: This file is #include'd by crypto.c.
 *
 */

#include "pkcs5.h"

static int
aes128_encrypt (Shishi * handle,
	     int keyusage,
	     char *key,
	     int keylen,
	     char *in,
	     int inlen,
	     char *out,
	     int *outlen)
{
  return simplified_encrypt (handle, keyusage, SHISHI_AES128_CTS_HMAC_SHA1_96,
			     key, keylen, in, inlen, out, outlen);
}

static int
aes128_decrypt (Shishi * handle,
	     int keyusage,
	     char *key,
	     int keylen,
	     char *in,
	     int inlen,
	     char *out,
	     int *outlen)
{
  return simplified_decrypt (handle, keyusage, SHISHI_AES128_CTS_HMAC_SHA1_96,
			     key, keylen, in, inlen, out, outlen);
}

static int
aes256_encrypt (Shishi * handle,
	     int keyusage,
	     char *key,
	     int keylen,
	     char *in,
	     int inlen,
	     char *out,
	     int *outlen)
{
  return simplified_encrypt (handle, keyusage, SHISHI_AES256_CTS_HMAC_SHA1_96,
			     key, keylen, in, inlen, out, outlen);
}

static int
aes256_decrypt (Shishi * handle,
	     int keyusage,
	     char *key,
	     int keylen,
	     char *in,
	     int inlen,
	     char *out,
	     int *outlen)
{
  return simplified_decrypt (handle, keyusage, SHISHI_AES256_CTS_HMAC_SHA1_96,
			     key, keylen, in, inlen, out, outlen);
}

static int
aes_string_to_key (Shishi * handle,
		   int keytype,
		   char *password,
		   int passwordlen,
		   char *salt,
		   int saltlen,
		   char *parameter,
		   char *outkey,
		   int keylen)
{
  unsigned char key[256/8];
  int iterations = 0x0000b000;
  int res;

  if (VERBOSECRYPTO(handle))
    {
      printf ("aes_string_to_key (password, salt)\n");

      printf ("\t ;; Password:\n");
      escapeprint (password, passwordlen);
      hexprint (password, passwordlen);
      puts ("");
      puts ("");

      printf ("\t ;; Salt:\n");
      escapeprint (salt, saltlen);
      hexprint (salt, saltlen);
      puts ("");
    }

  if (parameter)
    {
      iterations  = (parameter[0] & 0xFF) << 24;
      iterations |= (parameter[1] & 0xFF) << 16;
      iterations |= (parameter[2] & 0xFF) << 8;
      iterations |=  parameter[3] & 0xFF;
    }

  /* tkey = random2key(PBKDF2(passphrase, salt, iter_count, keylength)) */
  res = PBKDF2 (PKCS5_PRF_SHA1, password, passwordlen, salt, saltlen,
		iterations, keylen, key);
  if (res != PKCS5_OK)
  return res;

  /* key = DK(tkey, "kerberos") */
  res = shishi_dk (handle, keytype, key, keylen,
		   "kerberos", strlen ("kerberos"), outkey, keylen);
  if (res != SHISHI_OK)
    return res;

  if (VERBOSECRYPTO(handle))
    {
      printf ("aes_string_to_key (password, salt)\n");
      printf ("\t ;; Key:\n");
      hexprint (outkey, keylen);
      puts ("");
      binprint (outkey, keylen);
      puts ("");
    }

  return SHISHI_OK;
}

static int
aes128_string_to_key (Shishi * handle,
		      char *password,
		      int passwordlen,
		      char *salt,
		      int saltlen,
		      char *parameter,
		      char *outkey)
{
  int keytype = SHISHI_AES128_CTS_HMAC_SHA1_96;
  int keylen = shishi_cipher_keylen (keytype);

  return aes_string_to_key (handle, keytype, password, passwordlen,
			    salt, saltlen, parameter, outkey, keylen);
}

static int
aes256_string_to_key (Shishi * handle,
		      char *password,
		      int passwordlen,
		      char *salt,
		      int saltlen,
		      char *parameter,
		      char *outkey)
{
  int keytype = SHISHI_AES256_CTS_HMAC_SHA1_96;
  int keylen = shishi_cipher_keylen (keytype);

  return aes_string_to_key (handle, keytype, password, passwordlen,
			    salt, saltlen, parameter, outkey, keylen);
}

static int
aes128_random_to_key (Shishi * handle,
		      char *random,
		      int randomlen,
		      char *outkey)
{
  int keytype = SHISHI_AES128_CTS_HMAC_SHA1_96;
  int keylen = shishi_cipher_keylen (keytype);

  if (randomlen < keylen)
    return !SHISHI_OK;

  memcpy(outkey, random, keylen);

  return SHISHI_OK;
}

static int
aes256_random_to_key (Shishi * handle,
		      char *random,
		      int randomlen,
		      char *outkey)
{
  int keytype = SHISHI_AES256_CTS_HMAC_SHA1_96;
  int keylen = shishi_cipher_keylen (keytype);

  if (randomlen < keylen)
    return !SHISHI_OK;

  memcpy(outkey, random, keylen);

  return SHISHI_OK;
}
