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

#include "crypto-lowlevel.c"

static int
_shishi_cipher_confoundersize (int type);

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

#include "crypto-simplified.c"

#include "crypto-null.c"
#include "crypto-des.c"
#include "crypto-3des.c"
#include "crypto-aes.c"

/* Generic stuff */

typedef int (*Shishi_random_to_key_function) (Shishi * handle,
					      int keytype,
					      char *random,
					      int randomlen,
					      char *outkey);

typedef int (*Shishi_string_to_key_function) (Shishi * handle,
					      int keytype,
					      char *password,
					      int passwordlen,
					      char *salt,
					      int saltlen,
					      char *parameter,
					      char *outkey);

typedef int (*Shishi_encrypt_function) (Shishi * handle,
					int keyusage,
					int keytype,
					char *key,
					int keylen,
					char *in,
					int inlen,
					char *out,
					int *outlen);

typedef int (*Shishi_decrypt_function) (Shishi * handle,
					int keyusage,
					int keytype,
					char *key,
					int keylen,
					char *in,
					int inlen, 
					char *out,
					int *outlen);

struct cipherinfo
{
  int type;
  char *name;
  int blocksize;
  int minpadsize;
  int confoundersize;
  int keylen;
  int defaultcksumtype;
  Shishi_random_to_key_function random2key;
  Shishi_string_to_key_function string2key;
  Shishi_encrypt_function encrypt;
  Shishi_decrypt_function decrypt;
};
typedef struct cipherinfo cipherinfo;

cipherinfo null_info = {
  0,
  "NULL",
  1,
  0,
  0,
  0,
  SHISHI_RSA_MD5,
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
  SHISHI_RSA_MD5_DES,
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
  SHISHI_RSA_MD4_DES,
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
  SHISHI_RSA_MD5_DES,
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
  3*8,
  SHISHI_HMAC_SHA1_DES3_KD,
  des3_random_to_key,
  des3_string_to_key,
  simplified_encrypt,
  simplified_decrypt
};

cipherinfo aes128_cts_hmac_sha1_96_info = {
  17,
  "aes128-cts-hmac-sha1-96",
  16,
  0,
  16,
  128/8,
  SHISHI_HMAC_SHA1_96_AES128,
  aes128_random_to_key,
  aes128_string_to_key,
  simplified_encrypt,
  simplified_decrypt
};

cipherinfo aes256_cts_hmac_sha1_96_info = {
  18,
  "aes256-cts-hmac-sha1-96",
  16,
  0,
  16,
  256/8,
  SHISHI_HMAC_SHA1_96_AES256,
  aes256_random_to_key,
  aes256_string_to_key,
  simplified_encrypt,
  simplified_decrypt
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
 * shishi_cipher_defaultcksumtype:
 * @type: encryption type, see Shishi_etype.
 * 
 * Return associated checksum mechanism for the encryption type.
 **/
int
shishi_cipher_defaultcksumtype (int type)
{
  int i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->defaultcksumtype;

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
		      int keytype,
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
	      shishi_cipher_name (keytype));
      printf ("\t ;; password:\n");
      escapeprint (password, passwordlen);
      hexprint (password, passwordlen);
      puts ("");
      printf ("\t ;; salt:\n");
      escapeprint (salt, saltlen);
      hexprint (salt, saltlen);
      puts ("");
    }

  if (*outkeylen < shishi_cipher_keylen (keytype))
    {
      shishi_error_printf (handle, "Keylength %d too small for %s (%d)",
			   *outkeylen, shishi_cipher_name (keytype),
			   shishi_cipher_keylen (keytype));
      return !SHISHI_OK;
    }

  string2key = _shishi_cipher_string_to_key (keytype);
  if (string2key == NULL)
    {
      shishi_error_printf (handle, "Unsupported string_to_key() ekeytype %d",
			   keytype);
      return !SHISHI_OK;
    }
  else
    {
      res = (*string2key) (handle, keytype, password, passwordlen, 
			   salt, saltlen, parameter, outkey);
      *outkeylen = shishi_cipher_keylen (keytype);
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
 * @keytype: cryptographic encryption type, see Shishi_etype.
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
		      int keytype,
		      char *random,
		      int randomlen,
		      char *outkey,
		      int *outkeylen)
{
  Shishi_random_to_key_function random2key;
  int res;

  if (DEBUGCRYPTO(handle))
    {
      printf ("random_to_key (%s, random)\n", shishi_cipher_name (keytype));
      printf ("\t ;; random:\n");
      hexprint (random, randomlen);
      puts ("");
      binprint (random, randomlen);
      puts ("");
    }

  if (*outkeylen < shishi_cipher_keylen (keytype))
    {
      shishi_error_printf (handle, "Keylength %d too small for %s (%d)",
			   *outkeylen, shishi_cipher_name (keytype),
			   shishi_cipher_keylen (keytype));
      return !SHISHI_OK;
    }

  random2key = _shishi_cipher_random_to_key (keytype);
  if (random2key == NULL)
    {
      shishi_error_printf (handle, "Unsupported random_to_key() ekeytype %d",
			   keytype);
      return !SHISHI_OK;
    }
  else
    {
      res = (*random2key) (handle, keytype, random, randomlen, outkey);
      *outkeylen = shishi_cipher_keylen (keytype);
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
		 int keyusage,
		 int keytype,
		 char *key, 
		 int keylen,
		 char *in, 
		 int inlen,
		 char *out,
		 int *outlen)
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

  if (cksumtype == 0)
    cksumtype = shishi_cipher_defaultcksumtype (keytype);

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
		int keyusage,
		int keytype,
		char *key,
		int keylen,
		char *in,
		int inlen, 
		char *out,
		int *outlen)
{
  Shishi_encrypt_function encrypt;
  int res;

  if (DEBUGCRYPTO(handle))
    {
      printf ("encrypt (type=%s, usage=%d, key, in)\n", 
	      shishi_cipher_name (keytype), keyusage);
      printf ("\t ;; key (%d):\n", keylen);
      hexprint (key, keylen);
      puts ("");
      printf ("\t ;; in (%d):\n", inlen);
      escapeprint (in, inlen);
      hexprint (in, inlen);
      puts ("");
    }

  if (keylen != shishi_cipher_keylen (keytype))
    {
      shishi_error_printf (handle, "Keylength %d does not match %s (%d)",
			   keylen, shishi_cipher_name (keytype),
			   shishi_cipher_keylen (keytype));
      return !SHISHI_OK;
    }

  encrypt = _shishi_cipher_encrypt (keytype);
  if (encrypt == NULL)
    {
      shishi_error_printf (handle, "Unsupported string_to_key() ekeytype %d",
			   keytype);
      return !SHISHI_OK;
    }

  res = (*encrypt) (handle, keyusage, keytype, key, keylen, 
		    in, inlen, out, outlen);

  if (DEBUGCRYPTO(handle))
    {
      printf ("\t ;; encrypt out:\n");
      escapeprint (out, *outlen);
      hexprint (out, *outlen);
      puts ("");
    }

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
		int keyusage,
		int keytype,
		char *key, 
		int keylen,
		char *in, 
		int inlen, 
		char *out,
		int *outlen)
{
  Shishi_decrypt_function decrypt;
  int res;

  if (DEBUGCRYPTO(handle))
    {
      printf ("decrypt (type=%s, usage=%d, key, in)\n", 
	      shishi_cipher_name (keytype),
	      keyusage);
      printf ("\t ;; key (%d):\n", keylen);
      hexprint (key, keylen);
      puts ("");
      printf ("\t ;; in (%d):\n", inlen);
      escapeprint (in, inlen);
      hexprint (in, inlen);
      puts ("");
    }

  if (keylen != shishi_cipher_keylen (keytype))
    {
      shishi_error_printf (handle, "Keylength %d does not match %s (%d)",
			   keylen, shishi_cipher_name (keytype),
			   shishi_cipher_keylen (keytype));
      return !SHISHI_OK;
    }

  decrypt = _shishi_cipher_decrypt (keytype);
  if (decrypt == NULL)
    {
      shishi_error_printf (handle, "Unsupported string_to_key() eetype %d",
			   keytype);
      return !SHISHI_OK;
    }

  res = (*decrypt) (handle, keyusage, keytype, key, keylen, 
		    in, inlen, out, outlen);

  if (DEBUGCRYPTO(handle))
    {
      printf ("\t ;; decrypt out:\n");
      escapeprint (out, *outlen);
      hexprint (out, *outlen);
      puts ("");
    }

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
