/* crypto-aes.c	AES related RFC 1510 crypto functions
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
simplified_cipher (Shishi * handle,
		   int etype,
		   char *out,
		   int *outlen,
		   char *in,
		   int inlen,
		   char *key,
		   int keylen)
{
  int algo = GCRY_MD_SHA1;
  int hlen = gcry_md_get_algo_dlen(algo);
  int res;
  GCRY_MD_HD hd;
  int i;
  char *p;
  GCRY_CIPHER_HD ch;
  int j;
  char *tmp;
  int tmplen;
  int confounderlen = _shishi_cipher_confoundersize (etype);

  if (!hlen)
    return !SHISHI_OK;

  if (inlen + confounderlen + hlen > *outlen)
    {
      shishi_error_printf (handle, "inbuffer too large");
      return SHISHI_TOO_SMALL_BUFFER;
    }

  memset (out, 0, confounderlen);
  memcpy (out + confounderlen, in, inlen);

  res = shishi_randomize (handle, out, confounderlen);
  if (res != SHISHI_OK)
    return res;

  tmplen = inlen + confounderlen;

#if 0
  printf ("cksum random: ");
  for (i = 0; i < confounderlen; i++)
    printf ("%02X ", out[i] & 0xFF);
  printf ("\n");
#endif

  hd = gcry_md_open (algo, GCRY_MD_FLAG_HMAC);
  if (!hd)
    return !SHISHI_OK;

  gcry_md_write (hd, out, tmplen);
  p = gcry_md_read (hd, algo);

#if 0
  printf ("cksum hash: ");
  for (i = 0; i < hlen; i++)
    printf ("%02X ", p[i] & 0xFF);
  printf ("\n");
#endif

  ch = gcry_cipher_open (GCRY_CIPHER_AES,
			 GCRY_CIPHER_MODE_CBC,
			 GCRY_CIPHER_CBC_CTS);
  if (ch == NULL)
    {
      puts ("open fail");
      return !SHISHI_OK;
    }

  res = gcry_cipher_setkey (ch, key, keylen);
  if (res != GCRYERR_SUCCESS)
    {
      if (res == GCRYERR_WEAK_KEY)
	{
	  printf ("weak key\n");
	}
      else
	{
	  puts ("setkey fail");
	}
      return !SHISHI_OK;
    }

  res = gcry_cipher_setiv (ch, NULL, 0);
  if (res != 0)
    {
      printf ("iv res %d err %s\n", res, gcry_strerror (res));
    }

  res = gcry_cipher_encrypt (ch, out, tmplen, NULL, 0);
  if (res != 0)
    {
      printf ("crypt res %d err %s\n", res, gcry_strerror (res));
    }

  gcry_cipher_close (ch);

  memcpy (out + tmplen, p, hlen);
  gcry_md_close (hd);

  *outlen = tmplen + hlen;

  return SHISHI_OK;
}

static int
aes128_encrypt (Shishi * handle,
		char *out,
		int *outlen,
		char *in,
		int inlen, 
		char *key)
{
  return simplified_cipher (handle, SHISHI_AES128_CTS_HMAC_SHA1_96, 
			    out, outlen, 
			    in, inlen, 
			    key, 128/8);
}

static int
aes256_encrypt (Shishi * handle,
		char *out,
		int *outlen,
		char *in,
		int inlen, 
		char *key)
{
  return simplified_cipher (handle, SHISHI_AES256_CTS_HMAC_SHA1_96, 
			    out, outlen, 
			    in, inlen, 
			    key, 256/8);
}

static int
aes_string_to_key (Shishi * handle,
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

  if (DEBUGCRYPTO(handle))
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

  res = PBKDF2 (PKCS5_PRF_SHA1, password, passwordlen, salt, saltlen,
		iterations, keylen, key);
  if (res != PKCS5_OK)
  return res;

  res = shishi_dk (handle, SHISHI_AES128_CTS_HMAC_SHA1_96,
		   key, keylen, "kerberoskerberos", 
		   strlen ("kerberoskerberos"), 
		   outkey, keylen);
  if (res != SHISHI_OK)
    return res;

  if (DEBUGCRYPTO(handle))
    {
      printf ("\t;; aes_string_to_key key:\n");
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
  return aes_string_to_key (handle, password, passwordlen, salt, saltlen, 
			    parameter, outkey, 128/8);
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
  return aes_string_to_key (handle, password, passwordlen, salt, saltlen, 
			    parameter, outkey, 256/8);
}
