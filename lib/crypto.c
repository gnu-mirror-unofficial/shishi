/* crypto.c	RFC 1510 crypto functions
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
 */

#include "internal.h"

#include <gcrypt.h>

typedef enum {
  SHISHI_DERIVEKEYMODE_CHECKSUM,
  SHISHI_DERIVEKEYMODE_PRIVACY,
  SHISHI_DERIVEKEYMODE_INTEGRITY
} Shishi_derivekeymode;

#define MAX_DERIVEDKEY_LEN 50

/* Utilities */

static void
escapeprint (char *str, int len)
{
  int i;

  printf ("\t ;; `");
  for (i = 0; i < len; i++)
    if ((str[i] >= 'A' && str[i] <= 'Z') ||
	(str[i] >= 'a' && str[i] <= 'z') ||
	(str[i] >= '0' && str[i] <= '9') || str[i] == '.')
      printf ("%c", str[i] & 0xFF);
    else
      printf ("\\x%02x", str[i] & 0xFF);
  printf ("' (length %d bytes)\n", len);
}

static void
hexprint (char *str, int len)
{
  int i;

  printf ("\t ;; ");
  for (i = 0; i < len; i++)
    {
      printf ("%02x ", str[i] & 0xFF);
      if ((i + 1) % 8 == 0)
	printf (" ");
      if ((i + 1) % 16 == 0 && i + 1 < len)
	printf ("\n\t ;; ");
    }
}

static void
binprint (char *str, int len)
{
  int i;

  printf ("\t ;; ");
  for (i = 0; i < len; i++)
    {
      printf ("%d%d%d%d%d%d%d%d ",
	      str[i] & 0x80 ? 1 : 0,
	      str[i] & 0x40 ? 1 : 0,
	      str[i] & 0x20 ? 1 : 0,
	      str[i] & 0x10 ? 1 : 0,
	      str[i] & 0x08 ? 1 : 0,
	      str[i] & 0x04 ? 1 : 0,
	      str[i] & 0x02 ? 1 : 0, str[i] & 0x01 ? 1 : 0);
      if ((i + 1) % 3 == 0)
	printf (" ");
      if ((i + 1) % 6 == 0 && i + 1 < len)
	printf ("\n\t ;; ");
    }
}

static void
bin7print (char *str, int len)
{
  int i;

  printf ("\t ;; ");
  for (i = 0; i < len; i++)
    {
      printf ("%d%d%d%d%d%d%d ",
	      str[i] & 0x40 ? 1 : 0,
	      str[i] & 0x20 ? 1 : 0,
	      str[i] & 0x10 ? 1 : 0,
	      str[i] & 0x08 ? 1 : 0,
	      str[i] & 0x04 ? 1 : 0,
	      str[i] & 0x02 ? 1 : 0, str[i] & 0x01 ? 1 : 0);
      if ((i + 1) % 3 == 0)
	printf (" ");
      if ((i + 1) % 6 == 0 && i + 1 < len)
	printf ("\n\t ;; ");
    }
}

#define MAX_BLOCK_LEN 32

static int
gcrypt (Shishi * handle,
	int alg,
	char *out,
	int *outlen,
	char *in,
	int inlen, char *key, int keylen, int direction)
{
  int res;
  GCRY_CIPHER_HD ch;
  int j;
  char iv[MAX_BLOCK_LEN];
  char *tmp;
  int tmplen;

  ch = gcry_cipher_open (alg, GCRY_CIPHER_MODE_CBC, 0);
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

  if (gcry_cipher_get_algo_blklen(alg) > MAX_BLOCK_LEN)
    return !SHISHI_OK;
  memset (iv, 0, MAX_BLOCK_LEN);
  res = gcry_cipher_setiv (ch, iv, gcry_cipher_get_algo_blklen(alg));
  if (res != 0)
    {
      printf ("iv res %d err %s\n", res, gcry_strerror (res));
    }

  if ((inlen % 8) != 0)
    {
      tmplen = inlen;
      tmplen += 8 - tmplen % 8;
      tmp = (char *) malloc (tmplen);
      memcpy (tmp, in, inlen);
      memset (tmp + inlen, 0, tmplen - inlen);
    }
  else
    {
      tmp = in;
      tmplen = inlen;
    }

  if (direction)
    res = gcry_cipher_decrypt (ch, out, *outlen, tmp, tmplen);
  else
    res = gcry_cipher_encrypt (ch, out, *outlen, tmp, tmplen);

  if ((inlen % 8) != 0)
    free (tmp);

  if (res != 0)
    {
      printf ("crypt res %d err %s\n", res, gcry_strerror (res));
    }
  *outlen = tmplen;

  gcry_cipher_close (ch);

  return SHISHI_OK;
}

/* NULL */

static int
null_encrypt (Shishi * handle,
	      char *out,
	      int *outlen, char *in, int inlen, char *key)
{
  if (*outlen < inlen)
    return !SHISHI_OK;

  memcpy (out, in, inlen);
  *outlen = inlen;

  return SHISHI_OK;
}

static int
null_decrypt (Shishi * handle,
	      char *out,
	      int *outlen, char *in, int inlen, char *key)
{
  if (*outlen < inlen)
    return !SHISHI_OK;

  memcpy (out, in, inlen);
  *outlen = inlen;

  return SHISHI_OK;
}

#include "crypto-des.c"
#include "crypto-3des.c"
#include "crypto-aes.c"

/* Generic stuff */

typedef int (*Shishi_random_to_key_function) (Shishi * handle,
					      char *random,
					      char *key);

typedef int (*Shishi_string_to_key_function) (Shishi * handle,
					      char *password,
					      int passwordlen,
					      char *salt,
					      int saltlen,
					      char *parameter,
					      char *outkey);

typedef int (*Shishi_encrypt_function) (Shishi * handle,
					char *out,
					int *outlen,
					char *in,
					int inlen,
					char *key);

typedef int (*Shishi_decrypt_function) (Shishi * handle,
					char *out,
					int *outlen,
					char *in,
					int inlen, char *key);

typedef int (*Shishi_derivekey_function) (Shishi * handle,
					  int derivekeymode,
					  int keyusage,
					  char *key,
					  int keylen,
					  char *derivedkey,
					  int *derivedkeylen);

struct cipherinfo
{
  int type;
  char *name;
  int blocksize;
  int minpadsize;
  int confoundersize;
  int keylen;
  Shishi_random_to_key_function random2key;
  Shishi_string_to_key_function string2key;
  Shishi_encrypt_function encrypt;
  Shishi_decrypt_function decrypt;
  Shishi_derivekey_function derivekey;
};
typedef struct cipherinfo cipherinfo;

cipherinfo null_info = {
  0,
  "NULL",
  1,
  0,
  0,
  0,
  NULL,
  NULL,
  null_encrypt,
  null_decrypt
};

cipherinfo des_cbc_crc_info = {
  1,
  "des-cbc-crc",
  8,
  4,
  8,
  8,
  NULL,
  des_string_to_key,
  des_crc_encrypt,
  des_crc_decrypt
};

cipherinfo des_cbc_md4_info = {
  2,
  "des-cbc-md4",
  8,
  0,
  8,
  8,
  NULL,
  des_string_to_key,
  des_md4_encrypt,
  des_md4_decrypt
};

cipherinfo des_cbc_md5_info = {
  3,
  "des-cbc-md5",
  8,
  0,
  8,
  8,
  NULL,
  des_string_to_key,
  des_md5_encrypt,
  des_md5_decrypt
};

cipherinfo des3_cbc_sha1_kd_info = {
  16,
  "des3-cbc-sha1-kd",
  8,
  0,
  8,
  24,
  des3_random_to_key,
  des3_string_to_key,
  des3_cbc_sha1_kd_encrypt,
  des3_cbc_sha1_kd_decrypt,
  des3_derivekey
};

cipherinfo aes128_cts_hmac_sha1_96_info = {
  17,
  "aes128-cts-hmac-sha1-96",
  16,
  0,
  16,
  16,
  NULL,
  aes128_string_to_key,
  aes128_encrypt
};

cipherinfo aes256_cts_hmac_sha1_96_info = {
  18,
  "aes256-cts-hmac-sha1-96",
  16,
  0,
  16,
  32,
  NULL,
  aes256_string_to_key,
  aes256_encrypt
};

cipherinfo *ciphers[] = {
  &null_info,
  &des_cbc_crc_info,
  &des_cbc_md4_info,
  &des_cbc_md5_info,
  &des3_cbc_sha1_kd_info,
  &aes128_cts_hmac_sha1_96_info,
  &aes256_cts_hmac_sha1_96_info
};

static int
_shishi_cipher_blocksize (int type)
{
  int i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->blocksize;

  return -1;
}

static int
_shishi_cipher_minpadsize (int type)
{
  int i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->minpadsize;

  return -1;
}

static int
_shishi_cipher_confoundersize (int type)
{
  int i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->confoundersize;

  return -1;
}

static Shishi_random_to_key_function
_shishi_cipher_random_to_key (int type)
{
  int i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->random2key;

  return NULL;
}

static Shishi_string_to_key_function
_shishi_cipher_string_to_key (int type)
{
  int i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->string2key;

  return NULL;
}

static Shishi_encrypt_function
_shishi_cipher_encrypt (int type)
{
  int i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->encrypt;

  return NULL;
}

static Shishi_decrypt_function
_shishi_cipher_decrypt (int type)
{
  int i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->decrypt;

  return NULL;
}

static Shishi_derivekey_function
_shishi_cipher_derivekey (int type)
{
  int i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->derivekey;

  return NULL;
}

/**
 * shishi_cipher_name:
 * @type: encryption type, see Shishi_etype.
 * 
 * Return name of encryption type, e.g. "des3-cbc-sha1-kd".
 **/
const char *
shishi_cipher_name (int type)
{
  int i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    {
      if (type == ciphers[i]->type)
	return ciphers[i]->name;
    }

  return NULL;
}

/**
 * shishi_cipher_keylen:
 * @type: encryption type, see Shishi_etype.
 * 
 * Return length of key used in the encryption type.
 **/
int
shishi_cipher_keylen (int type)
{
  int i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->keylen;

  return -1;
}

/**
 * shishi_etype_parse:
 * @cipher: name of encryption type, e.g. "des3-cbc-sha1-kd".
 * 
 * Return encryption type corresponding to a string.
 **/
int
shishi_etype_parse (char *cipher)
{
  int i;
  char *endptr;

  i = strtol (cipher, &endptr, 0);

  if (endptr != cipher)
    return i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (strcasecmp (cipher, ciphers[i]->name) == 0)
      return ciphers[i]->type;

  return -1;
}


/**
 * shishi_string_to_key:
 * @handle: shishi handle as allocated by shishi_init().
 * @etype: cryptographic encryption type, see Shishi_etype.
 * @password: input array with password.
 * @passwordlen: length of input array with password.
 * @parameter: input array with opaque encryption type specific information.
 * @outkey: output array with key.
 * @outkeylen: on input, holds maximum size of output array, on output
 *             holds actual size of output array.
 * 
 * Convert a string (password) and some salt (realm and principal)
 * into a cryptographic key.  The parameter can be, and often is, NULL.
 *
 * If OUTKEY is NULL, this functions only set OUTKEYLEN.  This usage
 * may be used by the caller to allocate the proper buffer size.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_string_to_key (Shishi * handle,
		      int etype,
		      char *password,
		      int passwordlen,
		      char *salt,
		      int saltlen,
		      char *parameter,
		      char *outkey,
		      int *outkeylen)
{
  Shishi_string_to_key_function string2key;
  int res;

  if (DEBUGCRYPTO(handle))
    {
      printf ("string_to_key (%s, password, salt)\n",
	      shishi_cipher_name (etype));
      printf ("\t ;; password:\n");
      escapeprint (password, passwordlen);
      hexprint (password, passwordlen);
      puts ("");
      printf ("\t ;; salt:\n");
      escapeprint (salt, saltlen);
      hexprint (salt, saltlen);
      puts ("");
    }

  if (*outkeylen < shishi_cipher_keylen (etype))
    {
      shishi_error_printf (handle, "Keylength %d too small for %s (%d)",
			   *outkeylen, shishi_cipher_name (etype),
			   shishi_cipher_keylen (etype));
      return !SHISHI_OK;
    }

  string2key = _shishi_cipher_string_to_key (etype);
  if (string2key == NULL)
    {
      shishi_error_printf (handle, "Unsupported string_to_key() ekeytype %d",
			   etype);
      return !SHISHI_OK;
    }
  else
    {
      res = (*string2key) (handle, password, passwordlen, 
			   salt, saltlen, parameter, outkey);
      *outkeylen = shishi_cipher_keylen (etype);
    }

  if (DEBUGCRYPTO(handle))
    {
      printf ("\t ;; string_to_key key:\n");
      hexprint (outkey, *outkeylen);
      puts ("");
      binprint (outkey, *outkeylen);
      puts ("");
    }

  return res;
}

/**
 * shishi_random_to_key:
 * @handle: shishi handle as allocated by shishi_init().
 * @etype: cryptographic encryption type, see Shishi_etype.
 * @random: input array with random data.
 * @randomlen: length of input array with random data.
 * @outkey: output array with key.
 * @outkeylen: on input, holds maximum size of output array, on output
 *             holds actual size of output array.
 * 
 * Convert random data into a cryptographic key.
 * 
 * If OUTKEY is NULL, this functions only set OUTKEYLEN.  This usage
 * may be used by the caller to allocate the proper buffer size.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_random_to_key (Shishi * handle,
		      int etype,
		      char *random,
		      int randomlen,
		      char *outkey,
		      int *outkeylen)
{
  Shishi_random_to_key_function random2key;
  int res;

  if (DEBUGCRYPTO(handle))
    {
      printf ("random_to_key (%s, random)\n", shishi_cipher_name (etype));
      printf ("\t ;; random:\n");
      hexprint (random, randomlen);
      puts ("");
      binprint (random, randomlen);
      puts ("");
    }

  if (*outkeylen < shishi_cipher_keylen (etype))
    {
      shishi_error_printf (handle, "Keylength %d too small for %s (%d)",
			   *outkeylen, shishi_cipher_name (etype),
			   shishi_cipher_keylen (etype));
      return !SHISHI_OK;
    }

  random2key = _shishi_cipher_random_to_key (etype);
  if (random2key == NULL)
    {
      if (randomlen < *outkeylen)
	return !SHISHI_OK;
      memcpy(outkey, random, *outkeylen);
    }
  else
    {
      res = (*random2key) (handle, random, outkey);
      *outkeylen = shishi_cipher_keylen (etype);
    }

  if (DEBUGCRYPTO(handle))
    {
      printf ("\t ;; random_to_key key:\n");
      hexprint (outkey, *outkeylen);
      puts ("");
      binprint (outkey, *outkeylen);
      puts ("");
    }

  return res;
}

/**
 * shishi_checksum:
 * @handle: shishi handle as allocated by shishi_init().
 * @etype: cryptographic checksum type, see Shishi_cksumtype.
 * @out: output array with integrity protected data.
 * @outlen: on input, holds maximum size of output array, on output,
 *          holds actual size of output array.
 * @in: input array with data to integrity protect.
 * @inlen: size of input array with data to integrity protect.
 * @key: input array with cryptographic key to use.
 * @keylen: size of input array with cryptographic key.
 *
 * Integrity protect data using a cryptographic checksum suite.
 *
 * If OUT is NULL, this functions only set OUTLEN.  This usage may be
 * used by the caller to allocate the proper buffer size.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_checksum (Shishi * handle,
		 int cksumtype,
		 char *out,
		 int *outlen,
		 char *in, int inlen, char *key, int keylen)
{
  int res;

  if (DEBUGCRYPTO(handle))
    {
      printf ("checksum (%s, in, key)\n", shishi_cipher_name (cksumtype));
      printf ("\t ;; in:\n");
      escapeprint (in, inlen);
      hexprint (in, inlen);
      puts ("");
      printf ("\t ;; key:\n");
      escapeprint (key, keylen);
      hexprint (key, keylen);
      puts ("");
    }
  switch (cksumtype)
    {
    case SHISHI_RSA_MD4_DES:
      if (keylen < 8)
	res = !SHISHI_OK;
      else
	{
	  char buffer[BUFSIZ];
	  int buflen;
	  char cksumkey[8];
	  int i;

	  buflen = sizeof (buffer);
	  res = checksum_md4 (handle, buffer, &buflen, in, inlen);
	  if (res != SHISHI_OK)
	    {
	      shishi_error_set (handle, "checksum failed");
	      return res;
	    }

#if 0
	  printf ("cksum orig key:");
	  for (i = 0; i < 8; i++)
	    printf ("%02x ", key[i]);
	  printf ("\n");
#endif

	  memcpy (cksumkey, key, 8);

	  for (i = 0; i < 8; i++)
	    cksumkey[i] ^= 0xF0;

#if 0
	  printf ("cksum key:");
	  for (i = 0; i < 8; i++)
	    printf ("%02x ", cksumkey[i]);
	  printf ("\n");
#endif

	  res = des_encrypt (handle, out, outlen, buffer, buflen, cksumkey);
	  if (res != SHISHI_OK)
	    {
	      shishi_error_set (handle, "encrypt failed");
	      return res;
	    }
	}
      break;

    case SHISHI_RSA_MD5_DES:
      if (keylen < 8)
	res = !SHISHI_OK;
      else
	{
	  char buffer[BUFSIZ];
	  int buflen;
	  char cksumkey[8];
	  int i;

	  buflen = sizeof (buffer);
	  res = checksum_md5 (handle, buffer, &buflen, in, inlen);
	  if (res != SHISHI_OK)
	    {
	      shishi_error_set (handle, "checksum failed");
	      return res;
	    }

#if 0
	  printf ("cksum orig key:");
	  for (i = 0; i < 8; i++)
	    printf ("%02x ", key[i]);
	  printf ("\n");
#endif

	  memcpy (cksumkey, key, 8);

	  for (i = 0; i < 8; i++)
	    cksumkey[i] ^= 0xF0;

#if 0
	  printf ("cksum key:");
	  for (i = 0; i < 8; i++)
	    printf ("%02x ", cksumkey[i]);
	  printf ("\n");
#endif

	  res = des_encrypt (handle, out, outlen, buffer, buflen, cksumkey);
	  if (res != SHISHI_OK)
	    {
	      shishi_error_set (handle, "encrypt failed");
	      return res;
	    }
	}
      break;

    case SHISHI_HMAC_SHA1_DES3_KD:
      puts("iik");
      if (keylen < 24)
	res = !SHISHI_OK;
      else
	{
	  char buffer[BUFSIZ];
	  int buflen;
	  char cksumkey[8];
	  int i;

	  buflen = sizeof (buffer);
	  res = checksum_md5 (handle, buffer, &buflen, in, inlen);
	  if (res != SHISHI_OK)
	    {
	      shishi_error_set (handle, "checksum failed");
	      return res;
	    }

#if 0
	  printf ("cksum orig key:");
	  for (i = 0; i < 8; i++)
	    printf ("%02x ", key[i]);
	  printf ("\n");
#endif

	  memcpy (cksumkey, key, 8);

	  for (i = 0; i < 8; i++)
	    cksumkey[i] ^= 0xF0;

#if 0
	  printf ("cksum key:");
	  for (i = 0; i < 8; i++)
	    printf ("%02x ", cksumkey[i]);
	  printf ("\n");
#endif

	  res = des_encrypt (handle, out, outlen, buffer, buflen, cksumkey);
	  if (res != SHISHI_OK)
	    {
	      shishi_error_set (handle, "encrypt failed");
	      return res;
	    }
	}
      break;

    default:
      res = !SHISHI_OK;
      printf("unimplemented checksum type!\n");
      break;
    }

  if (DEBUGCRYPTO(handle))
    {
      printf ("\t ;; checksum out:\n");
      escapeprint (out, *outlen);
      hexprint (out, *outlen);
      puts ("");
    }

  return res;
}

int
shishi_derive_checksum (Shishi * handle,
			int cksumtype, int usage,
			char *out,
			int *outlen,
			char *in, int inlen, 
			char *key, int keylen)
{
  int derivedkeylen;
  int constantlen;
  char constant[5];
  char derivedkey[50];
  int res;

  if (cksumtype == SHISHI_HMAC_SHA1_DES3_KD)
    {
      derivedkeylen = keylen;
      constantlen = 5;
  
      usage = htonl(usage);
      memcpy(constant, &usage, 4);
      memcpy(constant + 4, "\x99", 1);

      res = shishi_dk (handle, SHISHI_DES3_CBC_HMAC_SHA1_KD, 
		       key, keylen, constant, constantlen,
		       derivedkey, derivedkeylen);
      if (res != SHISHI_OK)
	return res;
    }
  else
    {
      derivedkeylen = keylen;
      memcpy(derivedkey, key, keylen);
    }

  res = shishi_checksum (handle, cksumtype, out, outlen, 
			 in, inlen, derivedkey, derivedkeylen);

  return res;
}

/**
 * shishi_encrypt:
 * @handle: shishi handle as allocated by shishi_init().
 * @etype: cryptographic encryption type, see Shishi_etype.
 * @out: output array with encrypted data.
 * @outlen: on input, holds maximum size of output array, on output,
 *          holds actual size of output array.
 * @in: input array with data to encrypt.
 * @inlen: size of input array with data to encrypt.
 * @key: input array with cryptographic key to use.
 * @keylen: size of input array with cryptographic key.
 *
 * Encrypts data using a cryptographic encryption suite.
 * 
 * If OUT is NULL, this functions only set OUTLEN.  This usage may be
 * used by the caller to allocate the proper buffer size.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_encrypt (Shishi * handle,
		int etype,
		char *out,
		int *outlen,
		char *in, int inlen, char *key, int keylen)
{
  Shishi_encrypt_function encrypt;
  int res;

  if (DEBUGCRYPTO(handle))
    {
      printf ("encrypt (%s, in, key)\n", shishi_cipher_name (etype));
      printf ("\t ;; in:\n");
      escapeprint (in, inlen);
      hexprint (in, inlen);
      puts ("");
      printf ("\t ;; key:\n");
      hexprint (key, keylen);
      puts ("");
    }

  if (keylen != shishi_cipher_keylen (etype))
    {
      shishi_error_printf (handle, "Keylength %d does not match %s (%d)",
			   keylen, shishi_cipher_name (etype),
			   shishi_cipher_keylen (etype));
      return !SHISHI_OK;
    }

  encrypt = _shishi_cipher_encrypt (etype);
  if (encrypt == NULL)
    {
      shishi_error_printf (handle, "Unsupported string_to_key() eetype %d",
			   etype);
      return !SHISHI_OK;
    }

  res = (*encrypt) (handle, out, outlen, in, inlen, key);

  if (DEBUGCRYPTO(handle))
    {
      printf ("\t ;; encrypt out:\n");
      escapeprint (out, *outlen);
      hexprint (out, *outlen);
      puts ("");
    }

  return res;
}

int
shishi_derive_encrypt (Shishi * handle,
		       int etype, int usage,
		       char *out,
		       int *outlen,
		       char *in, int inlen, 
		       char *key, int keylen)
{
  Shishi_derivekey_function derivekey;
  char derivedkey[MAX_DERIVEDKEY_LEN];
  int derivedkeylen;
  int res;

  derivekey = _shishi_cipher_derivekey (etype);
  if (derivekey == NULL)
    {
      derivedkeylen = keylen;
      memcpy(derivedkey, key, keylen);
    }
  else
    {
      derivedkeylen = MAX_DERIVEDKEY_LEN;
      res = derivekey(handle, SHISHI_DERIVEKEYMODE_PRIVACY, usage, key, keylen,
		      derivedkey, &derivedkeylen);
      if (res != SHISHI_OK)
	return res;
    }

  res = shishi_encrypt(handle, etype, out, outlen, 
		       in, inlen, derivedkey, derivedkeylen);

  return res;
}

/**
 * shishi_decrypt:
 * @handle: shishi handle as allocated by shishi_init().
 * @etype: cryptographic encryption type, see Shishi_etype.
 * @out: output array with decrypted data.
 * @outlen: on input, holds maximum size of output array, on output,
 *          holds actual size of output array.
 * @in: input array with data to decrypt.
 * @inlen: size of input array with data to decrypt.
 * @key: input array with cryptographic key to use.
 * @keylen: size of input array with cryptographic key.
 *
 * Decrypts data using a cryptographic encryption suite.
 *
 * If OUT is NULL, this functions only set OUTLEN.  This usage may be
 * used by the caller to allocate the proper buffer size.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_decrypt (Shishi * handle,
		int etype,
		char *out,
		int *outlen,
		char *in, int inlen, char *key, int keylen)
{
  Shishi_decrypt_function decrypt;
  int res;

  if (DEBUGCRYPTO(handle))
    {
      printf ("decrypt (%s, in, key)\n", shishi_cipher_name (etype));
      printf ("\t ;; in:\n");
      escapeprint (in, inlen);
      hexprint (in, inlen);
      puts ("");
      printf ("\t ;; key:\n");
      hexprint (key, keylen);
      puts ("");
    }

  if (keylen != shishi_cipher_keylen (etype))
    {
      shishi_error_printf (handle, "Keylength %d does not match %s (%d)",
			   keylen, shishi_cipher_name (etype),
			   shishi_cipher_keylen (etype));
      return !SHISHI_OK;
    }

  decrypt = _shishi_cipher_decrypt (etype);
  if (decrypt == NULL)
    {
      shishi_error_printf (handle, "Unsupported string_to_key() eetype %d",
			   etype);
      return !SHISHI_OK;
    }

  res = (*decrypt) (handle, out, outlen, in, inlen, key);

  if (DEBUGCRYPTO(handle))
    {
      printf ("\t ;; decrypt out:\n");
      escapeprint (out, *outlen);
      hexprint (out, *outlen);
      puts ("");
    }

  return res;
}

int
shishi_derive_decrypt (Shishi * handle,
		       int etype, int usage,
		       char *out,
		       int *outlen,
		       char *in, int inlen, 
		       char *key, int keylen)
{
  Shishi_derivekey_function derivekey;
  char derivedkey[MAX_DERIVEDKEY_LEN];
  int derivedkeylen;
  int res;

  derivekey = NULL;//_shishi_cipher_derivekey (etype);
  if (derivekey == NULL)
    {
      derivedkeylen = keylen;
      memcpy(derivedkey, key, keylen);
    }
  else
    {
      derivedkeylen = MAX_DERIVEDKEY_LEN;
      res = derivekey(handle, SHISHI_DERIVEKEYMODE_PRIVACY, usage, key, keylen,
		      derivedkey, &derivedkeylen);
      if (res != SHISHI_OK)
	return res;
    }

  res = shishi_decrypt(handle, etype, out, outlen, 
		       in, inlen, derivedkey, derivedkeylen);

  return res;
}

/**
 * shishi_randomize:
 * @handle: shishi handle as allocated by shishi_init().
 * @data: output array to be filled with random data.
 * @datalen: size of output array.
 * 
 * Store cryptographically strong random data in the provided buffer.
 * 
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_randomize (Shishi * handle, char *data, int datalen)
{
  char tmp[BUFSIZ];

  memcpy (data, tmp, datalen < BUFSIZ ? datalen : BUFSIZ);

  gcry_randomize (data, datalen, GCRY_WEAK_RANDOM);

  if (memcmp (data, tmp, datalen < BUFSIZ ? datalen : BUFSIZ) == 0)
    {
      shishi_error_set (handle, "gcry_randomize() failed to provide entropy");
      return !SHISHI_OK;
    }

  return SHISHI_OK;
}

/**
 * shishi_n_fold:
 * @handle: shishi handle as allocated by shishi_init().
 * @in: input array with data to decrypt.
 * @inlen: size of input array with data to decrypt ("M").
 * @out: output array with decrypted data.
 * @outlen: size of output array ("N").
 * 
 * Fold data into a fixed length output array, with the intent to give
 * each input bit approximately equal weight in determining the value
 * of each output bit.
 *
 * The algorithm is from "A Better Key Schedule For DES-like Ciphers"
 * by Uri Blumenthal and Steven M. Bellovin,
 * <URL:http://www.research.att.com/~smb/papers/ides.pdf>, although
 * the sample vectors provided by the paper are incorrect.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_n_fold (Shishi * handle,
	       char *in, int inlen, char *out, int outlen)
{
  int m = inlen;
  int n = outlen;
  char *buf = NULL;
  char *a = NULL;
  int lcmmn = 0;
  int i = 0;
  int k = 0;

  /* 
     To n-fold a number X, replicate the input value to a length that is
     the least common multiple of n and the length of X. Before each
     repetition, the input is rotated to the right by 13 bit
     positions. The successive n-bit chunks are added together using
     1's-complement addition (that is, addition with end-around carry)
     to yield a n-bit result denoted <X>_n.
   */

  a = (char *) malloc (m);
  if (a == NULL)
    return SHISHI_MALLOC_ERROR;
  memcpy (a, in, m);

  lcmmn = lcm (m, n);

  if (DEBUGCRYPTO(handle))
    {
      printf ("%d-fold (string)\n", n * 8);
      printf ("\t ;; string length %d bytes %d bits\n", m, m * 8);
      escapeprint (a, m);
      hexprint (a, m);
      puts ("");
      printf ("\t ;; lcm(%d, %d) = lcm(%d, %d) = %d\n",
	      8 * m, 8 * n, m, n, lcmmn);
      puts ("");
    }

  buf = (char *) malloc (lcmmn);
  if (buf == NULL)
    return SHISHI_MALLOC_ERROR;

  /* Replicate the input th the LCMMN length */
  for (i = 0; i < (lcmmn / m); i++)
    {
      if (DEBUGCRYPTO(handle))
	{
	  printf ("\t ;; %d-th replication\n", i + 1);
	  printf ("string = rot13(string)\n");
	}

      memcpy ((char *) &buf[i * m], a, m);
      rot13 (handle, a, a, m);

      if (DEBUGCRYPTO(handle))
	puts("");
    }

  memset (out, 0, n);		/* just in case */

  if (DEBUGCRYPTO(handle))
    {
      printf ("\t ;; replicated string (length %d):\n", lcmmn);
      hexprint (buf, lcmmn);
      puts ("");
      binprint (buf, lcmmn);
      puts ("");
      printf ("sum = 0\n");
    }

  /* Now we view the buf as set of n-byte strings 
     Add the n-byte long chunks together, using 
     one's complement addition, storing the
     result in the output string. */

  for (i = 0; i < (lcmmn / n); i++)
    {
      if (DEBUGCRYPTO(handle))
	{
	  printf ("\t ;; %d-th one's complement addition sum\n", i + 1);
	  printf ("\t ;; sum:\n");
	  hexprint (out, n);
	  puts ("");
	  binprint (out, n);
	  puts ("");
	  printf ("\t ;; A (offset %d):\n", i * n);
	  hexprint (&buf[i * n], n);
	  puts ("");
	  binprint (&buf[i * n], n);
	  puts ("");
	  printf ("sum = ocadd(sum, A);\n");
	}

      ocadd (out, (char *) &buf[i * n], out, n);

      if (DEBUGCRYPTO(handle))
	{
	  printf ("\t ;; sum:\n");
	  hexprint (out, n);
	  puts ("");
	  binprint (out, n);
	  puts ("");
	  puts ("");
	}
    }

  if (DEBUGCRYPTO(handle))
    {
      printf ("\t ;; nfold\n");
      hexprint (out, n);
      puts ("");
      binprint (out, n);
      puts ("");
      puts ("");
    }

  free (buf);
  free (a);

  return SHISHI_OK;
}

#define MAX_DR_CONSTANT 1024

/**
 * shishi_dr:
 * @handle: shishi handle as allocated by shishi_init().
 * @etype: cryptographic encryption type, see Shishi_etype.
 * @key: input array with cryptographic key to use.
 * @keylen: size of input array with cryptographic key.
 * @constant: input array with the constant string.
 * @constantlen: size of input array with the constant string.
 * @derivedrandom: output array with derived random data.
 * @derivedrandomlen: size of output array with derived random data.
 * 
 * Derive "random" data from a key and a constant thusly:
 * DR(KEY, CONSTANT) = TRUNCATE(DERIVEDRANDOMLEN, 
 *                              SHISHI_ENCRYPT(KEY, CONSTANT)).
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_dr (Shishi * handle,
	   int etype,
	   char *key,
	   int keylen,
	   char *constant,
	   int constantlen,
	   char *derivedrandom, int derivedrandomlen)
{
  char cipher[MAX_DR_CONSTANT];
  char plaintext[MAX_DR_CONSTANT];
  char nfoldconstant[MAX_DR_CONSTANT];
  int len, totlen, cipherlen;
  int res;

  if (DEBUGCRYPTO(handle))
    {
      printf ("dr (%s, key, constant, %d)\n",
	      shishi_cipher_name (etype), derivedrandomlen);
      printf ("\t ;; key (length %d):\n", keylen);
      hexprint (key, keylen);
      puts ("");
      binprint (key, keylen);
      puts ("");
      printf ("\t ;; constant:\n", constant);
      escapeprint (constant, constantlen);
      hexprint (constant, constantlen);
      puts ("");
      binprint (constant, constantlen);
      puts ("");
      puts ("");
    }

  if (constantlen > MAX_DR_CONSTANT)
    return !SHISHI_OK;

  if (constantlen == 8)
    {
      memcpy (nfoldconstant, constant, constantlen);
    }
  else
    {
      res = shishi_n_fold (handle, constant, constantlen, nfoldconstant, 8);
      if (res != SHISHI_OK)
	return res;
    }

  if (DEBUGCRYPTO(handle))
    {
      printf ("\t ;; possibly nfolded constant (length %d):\n", 8);
      escapeprint (nfoldconstant, 8);
      hexprint (nfoldconstant, 8);
      puts ("");
      binprint (nfoldconstant, 8);
      puts ("");
    }

  memcpy (plaintext, nfoldconstant, 8);

  totlen = 0;
  do
    {
      cipherlen = sizeof (cipher);
      res = shishi_encrypt (handle, etype,
			    cipher, &cipherlen, plaintext, 8, key, keylen);
      if (res != SHISHI_OK)
	return res;
      memcpy (derivedrandom + totlen, cipher, cipherlen);
      memcpy (plaintext, cipher, cipherlen);
      totlen += cipherlen;
    }
  while (totlen < derivedrandomlen);

  if (DEBUGCRYPTO(handle))
    {
      printf ("\t ;; derived random (length %d):\n", derivedrandomlen);
      hexprint (derivedrandom, derivedrandomlen);
      puts ("");
      binprint (derivedrandom, derivedrandomlen);
      puts ("");
    }

  return SHISHI_OK;
}

/**
 * shishi_dk:
 * @handle: shishi handle as allocated by shishi_init().
 * @etype: cryptographic encryption type, see Shishi_etype.
 * @key: input array with cryptographic key to use.
 * @keylen: size of input array with cryptographic key.
 * @constant: input array with the constant string.
 * @constantlen: size of input array with the constant string.
 * @derivedkey: output array with derived key.
 * @derivedkeylen: size of output array with derived key.
 * 
 * Derive a key from a key and a constant thusly:
 * DK(KEY, CONSTANT) = SHISHI_RANDOM-TO-KEY(SHISHI_DR(KEY, CONSTANT)).
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_dk (Shishi * handle,
	   int etype,
	   char *key,
	   int keylen,
	   char *constant,
	   int constantlen, char *derivedkey, int derivedkeylen)
{
  char *tmp;
  int tmplen, len;
  int res;

  if (DEBUGCRYPTO(handle))
    {
      printf ("dk (%s, key, constant, %d)\n",
	      shishi_cipher_name (etype), derivedkeylen);
      printf ("\t ;; key (length %d):\n", keylen);
      hexprint (key, keylen);
      puts ("");
      binprint (key, keylen);
      puts ("");
      printf ("\t ;; constant:\n");
      escapeprint (constant, constantlen);
      hexprint (constant, constantlen);
      puts ("");
      binprint (constant, constantlen);
      puts ("");
      puts ("");
    }

  tmplen = derivedkeylen;
  tmp = (char *) malloc (tmplen);
  if (tmp == NULL)
    return SHISHI_MALLOC_ERROR;

  res = shishi_dr (handle,
		   etype, key, keylen, constant, constantlen, tmp, tmplen);
  if (res != SHISHI_OK)
    return res;

  len = derivedkeylen;
  res = shishi_random_to_key (handle, etype, tmp, tmplen, derivedkey, &len);
  if (res != SHISHI_OK)
    return res;

  free (tmp);

  return SHISHI_OK;
}
