/* crypto.c	crypto functions
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

static int
simplified_dencrypt (Shishi * handle,
		     int keytype,
		     char *out,
		     int *outlen,
		     char *in,
		     int inlen, 
		     char *key, int keylen, 
		     int direction)
{
  int res;
  GCRY_CIPHER_HD ch;
  int j;
  int alg = 0;
  int mode = GCRY_CIPHER_MODE_CBC;
  int flags = 0;

  switch (keytype)
    {
    case SHISHI_DES3_CBC_HMAC_SHA1_KD:
      alg = GCRY_CIPHER_3DES;
      break;

    case SHISHI_DES_CBC_CRC:
    case SHISHI_DES_CBC_MD4:
    case SHISHI_DES_CBC_MD5:
      alg = GCRY_CIPHER_DES;
      break;

    case SHISHI_AES128_CTS_HMAC_SHA1_96:
    case SHISHI_AES256_CTS_HMAC_SHA1_96:
      alg = GCRY_CIPHER_AES;
      flags = GCRY_CIPHER_CBC_CTS;
      break;
    }

  ch = gcry_cipher_open (alg, mode, flags);
  if (ch == NULL)
    return SHISHI_GCRYPT_ERROR;

  res = gcry_cipher_setkey (ch, key, keylen);
  if (res == GCRYERR_SUCCESS)
    res = gcry_cipher_setiv (ch, NULL, 0);

  if (res == GCRYERR_SUCCESS)
    res = direction ? 
      gcry_cipher_decrypt (ch, out, *outlen, in, inlen) : 
      gcry_cipher_encrypt (ch, out, *outlen, in, inlen);

  if (res != GCRYERR_SUCCESS)
    {
      puts(gcry_strerror (res));
      shishi_error_set (handle, gcry_strerror (res));
      return SHISHI_GCRYPT_ERROR;
    }

  *outlen = inlen;

  gcry_cipher_close (ch);

  return SHISHI_OK;
}

static int
simplified_hmac (Shishi * handle, 
		 int keytype, char *key, int keylen,
		 char *in, int inlen,
		 char *out, int outlen)
{
  GCRY_MD_HD mdh;
  int halg = GCRY_MD_SHA1;
  int hlen = gcry_md_get_algo_dlen(halg);
  char *hash;
  int res;

  mdh = gcry_md_open (halg, GCRY_MD_FLAG_HMAC);
  if (mdh == NULL)
    return SHISHI_GCRYPT_ERROR;

  res = gcry_md_setkey (mdh, key, keylen);
  if (res != GCRYERR_SUCCESS)
    {
      shishi_error_set (handle, gcry_strerror (res));
      return SHISHI_GCRYPT_ERROR;
    }

  gcry_md_write (mdh, in, inlen);
  
  hash = gcry_md_read (mdh, halg);
  if (hash == NULL)
    return SHISHI_GCRYPT_ERROR;

  memcpy(out, hash, outlen < hlen ? outlen : hlen);

  gcry_md_close (mdh);

  return SHISHI_OK;
}

static int
simplified_hmac_verify (Shishi * handle, 
			int keytype, char *key, int keylen,
			char *in, int inlen,
			char *hmac, int hmaclen)
{
  char hash[MAX_HASH_LEN];
  int res;

  res = simplified_hmac(handle, keytype, key, keylen, in, inlen, 
			hash, hmaclen);
  if (res != SHISHI_OK)
    return res;

  if (memcmp(hash, hmac, hmaclen) != 0)
    {
      if (DEBUG(handle))
	printf ("verify fail\n");
      return SHISHI_CRYPTO_ERROR;
    }

  return SHISHI_OK;
}

typedef enum {
  SHISHI_DERIVEKEYMODE_CHECKSUM,
  SHISHI_DERIVEKEYMODE_PRIVACY,
  SHISHI_DERIVEKEYMODE_INTEGRITY
} Shishi_derivekeymode;

static int
simplified_derivekey (Shishi *handle,
		      int derivekeymode,
		      int keyusage,
		      int keytype,
		      char *key,
		      int keylen,
		      char *derivedkey,
		      int *derivedkeylen)
{
  char constant[5];
  int res;

  if (DEBUGCRYPTO(handle))
    {
      printf ("simplified_derivekey\n");
      printf ("\t ;; mode %d (%s)\n", derivekeymode,
	      derivekeymode == SHISHI_DERIVEKEYMODE_CHECKSUM ? "checksum" :
	      derivekeymode == SHISHI_DERIVEKEYMODE_INTEGRITY ? "integrity" :
	      derivekeymode == SHISHI_DERIVEKEYMODE_PRIVACY ? "privacy" : 
	      "base-key");
      hexprint (key, keylen);
      puts ("");
    }

  if (*derivedkeylen < keylen)
    return SHISHI_DERIVEDKEY_TOO_SMALL;
  *derivedkeylen = keylen;

  if (keyusage)
    {
      uint32_t tmp = htonl(keyusage);
      memcpy(constant, &tmp, 4);
      if (derivekeymode == SHISHI_DERIVEKEYMODE_CHECKSUM)
	constant[4] = '\x99';
      else if (derivekeymode == SHISHI_DERIVEKEYMODE_INTEGRITY)
	constant[4] = '\x55';
      else /* if (derivekeymode == SHISHI_DERIVEKEYMODE_PRIVACY) */
	constant[4] = '\xAA';
      
      res = shishi_dk (handle, keytype, key, keylen, constant, 5, 
		       derivedkey, *derivedkeylen);
    }
  else
    {
      memcpy(derivedkey, key, keylen);
    }

  if (DEBUGCRYPTO(handle))
    {
      printf ("\t ;; simplified_derivekey out (%d):\n", *derivedkeylen);
      hexprint (derivedkey, *derivedkeylen);
      puts ("");
    }

  return res;
}

static int
simplified_encrypt (Shishi * handle,
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
  int padzerolen = 0;

  if ((keytype == SHISHI_DES3_CBC_HMAC_SHA1_KD ||
       keytype == SHISHI_DES_CBC_CRC ||
       keytype == SHISHI_DES_CBC_MD4 ||
       keytype == SHISHI_DES_CBC_MD5) && (inlen % 8) != 0)
    while (((inlen + padzerolen) % 8) != 0)
     padzerolen++;

  if (keyusage != 0)
    {
      char derivedkey[MAX_KEY_LEN];
      int derivedkeylen;
      char *buffer;
      int buflen;
      int blen = shishi_cipher_blocksize (keytype);
      int halg = GCRY_MD_SHA1;
      int hlen = gcry_md_get_algo_dlen(halg);
      int len;

      buflen = inlen + blen + padzerolen;
      buffer = malloc(buflen);
      if (!buffer)
	return SHISHI_MALLOC_ERROR;

      res = shishi_randomize (handle, buffer, blen);
      if (res != SHISHI_OK)
	return res;

      memcpy(buffer + blen, in, inlen);
      memset(buffer + blen + inlen, 0, padzerolen);

      derivedkeylen = MAX_KEY_LEN;
      res = simplified_derivekey(handle, SHISHI_DERIVEKEYMODE_PRIVACY, 
				 keyusage, keytype, key, keylen,
				 derivedkey, &derivedkeylen);
      if (res != SHISHI_OK)
	return res;

      len = *outlen;
      res = simplified_dencrypt (handle, keytype, out, &len, buffer, buflen,
				 derivedkey, derivedkeylen, 0);
      if (res != SHISHI_OK)
	return res;
      
      derivedkeylen = MAX_KEY_LEN;
      res = simplified_derivekey(handle, SHISHI_DERIVEKEYMODE_INTEGRITY,
				 keyusage, keytype, key, keylen,
				 derivedkey, &derivedkeylen);
      if (res != SHISHI_OK)
	return res;
      
      res = simplified_hmac (handle, keytype, derivedkey, derivedkeylen, 
			     buffer, buflen, out + len, hlen);
      if (res != SHISHI_OK)
	return res;

      *outlen = buflen + hlen;
    }
  else
    {
      res = simplified_dencrypt (handle, keytype, out, outlen, in, inlen, 
				 key, keylen, 0);
    }

  return res;
}

static int
simplified_decrypt (Shishi * handle,
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

  if (keyusage)
    {
      char derivedkey[MAX_KEY_LEN];
      int derivedkeylen;
      int blen = shishi_cipher_blocksize (keytype);
      int halg = GCRY_MD_SHA1;
      int hlen = gcry_md_get_algo_dlen(halg);
      int len;

      derivedkeylen = MAX_KEY_LEN;
      res = simplified_derivekey(handle, SHISHI_DERIVEKEYMODE_PRIVACY, 
				 keyusage, keytype, key, keylen,
				 derivedkey, &derivedkeylen);
      if (res != SHISHI_OK)
	return res;

      len = *outlen;
      res = simplified_dencrypt (handle, keytype, out, &len, in, inlen - hlen,
			       derivedkey, derivedkeylen, 1);
      if (res != SHISHI_OK)
	return res;
      
      derivedkeylen = MAX_KEY_LEN;
      res = simplified_derivekey(handle, SHISHI_DERIVEKEYMODE_INTEGRITY,
				 keyusage, keytype, key, keylen,
				 derivedkey, &derivedkeylen);
      if (res != SHISHI_OK)
	return res;

      res = simplified_hmac_verify (handle, keytype, derivedkey, derivedkeylen,
				    out, len, in + inlen - hlen, hlen);
				  
      if (res != SHISHI_OK)
	return res;

      memmove(out, out + blen, len - blen);
      *outlen = len - blen;
    }
  else
    {
      res = simplified_dencrypt (handle, keytype, out, outlen, in, inlen, 
			       key, keylen, 1);
    }

  return res;
}

static int
gcd (int a, int b)
{
  if (b == 0)
    return a;
  else
    return gcd (b, a % b);
}

static int
lcm (int a, int b)
{
  return a * b / gcd (a, b);
}

static int
rot13 (Shishi *handle, unsigned char *in, unsigned char *out, int len)
{
  if (DEBUGCRYPTO(handle))
    {
      printf ("\t ;; rot 13 in:\n");
      escapeprint (in, len);
      hexprint (in, len);
      puts ("");
      binprint (in, len);
      puts ("");
    }

  if (len == 1)
    {
      out[0] = 
	(in[0] >> 5) & 0x01 |
	(in[0] >> 5) & 0x02 |
	(in[0] >> 5) & 0x04 |
	(in[0] << 3) & 0x08 |
	(in[0] << 3) & 0x10 |
	(in[0] << 3) & 0x20 |
	(in[0] << 3) & 0x40 |
	(in[0] << 3) & 0x80;
    }
  else if (len > 1)
    {
      unsigned char nexttolast, last;
      int i;

      nexttolast = in[len - 2];
      last = in[len - 1];

      for (i = len * 8 - 1; i >= 13; i--)
	{
	  unsigned int pos = i / 8;
	  unsigned char mask = ~(1 << (7 - i % 8));
	  unsigned int pos2 = (i - 13) / 8;
	  unsigned char mask2 = (1 << (7 - (i - 13) % 8));

	  out[pos] = (out[pos] & mask) |
	    (((in[pos2] & mask2) ? 0xFF : 0x00) & ~mask);
	}
      out[0] = (nexttolast << 3) | (last >> 5);
      out[1] = (in[1] & ~(0xFF & (0xFF << 3))) | (0xFF & (last << 3));
    }

  if (DEBUGCRYPTO(handle))
    {
      printf ("\t ;; rot13 out:\n");
      escapeprint (out, len);
      hexprint (out, len);
      puts("");
      binprint (out, len);
      puts ("");
    }

  return SHISHI_OK;
}

static int
ocadd (unsigned char *add1, unsigned char *add2, unsigned char *sum, int len)
{
  int i;
  int carry = 0;

  for (i = len - 1; i >= 0; i--)
    {
      unsigned int tmpsum = add1[i] + add2[i];

      sum[i] = 0xFF & (tmpsum + carry);
      if ((tmpsum + carry) & ~0xFF)
	carry = 1;
      else
	carry = 0;
    }
  if (carry)
    {
      int done = 0;

      for (i = len - 1; i >= 0; i--)
	if (sum[i] != 0xFF)
	  {
	    sum[i]++;
	    done = 1;
	    break;
	  }

      if (!done)
	memset (sum, 0, len);
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
  int blocksize = shishi_cipher_blocksize (etype);
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

  if (constantlen == blocksize)
    {
      memcpy (nfoldconstant, constant, constantlen);
    }
  else
    {
      res = shishi_n_fold (handle, constant, constantlen, nfoldconstant, 
			   blocksize);
      if (res != SHISHI_OK)
	return res;
    }

  if (DEBUGCRYPTO(handle))
    {
      printf ("\t ;; possibly nfolded constant (length %d):\n", blocksize);
      escapeprint (nfoldconstant, blocksize);
      hexprint (nfoldconstant, blocksize);
      puts ("");
      binprint (nfoldconstant, blocksize);
      puts ("");
    }

  memcpy (plaintext, nfoldconstant, blocksize);

  totlen = 0;
  do
    {
      cipherlen = sizeof (cipher);
      res = shishi_encrypt (handle, 0, etype, key, keylen, 
			    plaintext, blocksize, cipher, &cipherlen);
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

#include "crypto-null.c"
#include "crypto-des.c"
#include "crypto-3des.c"
#include "crypto-aes.c"

typedef int (*Shishi_random_to_key_function) (Shishi * handle,
					      char *random,
					      int randomlen,
					      char *outkey);

typedef int (*Shishi_string_to_key_function) (Shishi * handle,
					      char *password,
					      int passwordlen,
					      char *salt,
					      int saltlen,
					      char *parameter,
					      char *outkey);

typedef int (*Shishi_encrypt_function) (Shishi * handle,
					int keyusage,
					char *key,
					int keylen,
					char *in,
					int inlen,
					char *out,
					int *outlen);

typedef int (*Shishi_decrypt_function) (Shishi * handle,
					int keyusage,
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
  des3_encrypt,
  des3_decrypt
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
  aes128_encrypt,
  aes128_decrypt
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
  aes256_encrypt,
  aes256_decrypt
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
  char *p;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    {
      if (type == ciphers[i]->type)
	return ciphers[i]->name;
    }

  shishi_asprintf (&p, "unknown cipher %d", type);
  return p;
}

int
shishi_cipher_blocksize (int type)
{
  int i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->blocksize;

  return -1;
}

int
shishi_cipher_minpadsize (int type)
{
  int i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->minpadsize;

  return -1;
}

int
shishi_cipher_confoundersize (int type)
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

  res = (*string2key) (handle, password, passwordlen, 
		       salt, saltlen, parameter, outkey);
  *outkeylen = shishi_cipher_keylen (keytype);

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

  res = (*random2key) (handle, random, randomlen, outkey);
  *outkeylen = shishi_cipher_keylen (keytype);

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

	  memcpy (cksumkey, key, 8);

	  for (i = 0; i < 8; i++)
	    cksumkey[i] ^= 0xF0;

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

	  memcpy (cksumkey, key, 8);

	  for (i = 0; i < 8; i++)
	    cksumkey[i] ^= 0xF0;

	  res = des_encrypt (handle, out, outlen, buffer, buflen, cksumkey);
	  if (res != SHISHI_OK)
	    {
	      shishi_error_set (handle, "encrypt failed");
	      return res;
	    }
	}
      break;

    case SHISHI_HMAC_SHA1_DES3_KD:
      {
	char derivedkey[MAX_KEY_LEN];
	int derivedkeylen;
	int halg = GCRY_MD_SHA1; /* XXX hide this in crypto-lowlevel.c */
	int hlen = gcry_md_get_algo_dlen(halg);
	int i;

	derivedkeylen = MAX_KEY_LEN;
	res = simplified_derivekey(handle, SHISHI_DERIVEKEYMODE_CHECKSUM, 
				   keyusage, keytype, key, keylen,
				   derivedkey, &derivedkeylen);
	if (res != SHISHI_OK)
	  return res;

	res = simplified_hmac (handle, keytype, derivedkey, derivedkeylen, 
			       in, inlen, out, hlen);
	if (res != SHISHI_OK)
	  {
	    shishi_error_set (handle, "verify failed");
	    return res;
	  }
	*outlen = hlen;
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

  res = (*encrypt) (handle, keyusage, key, keylen, 
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

  res = (*decrypt) (handle, keyusage, key, keylen, 
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
