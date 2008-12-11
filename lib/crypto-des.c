/* crypto-des.c --- DES crypto functions.
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
raw_des_checksum0 (Shishi * handle, int algo,
		   const char *in, size_t inlen, char *out, size_t * outlen)
{
  char *tmp;
  size_t tmplen;
  char *p;
  int blen = 8;
  int hlen = (algo == SHISHI_DES_CBC_CRC) ? 4 : 16;
  int rc;

  rc = shishi_randomize (handle, 0, out, blen);
  if (rc != SHISHI_OK)
    return rc;

  tmplen = blen + inlen;
  tmp = xmalloc (tmplen);

  memcpy (tmp, out, blen);
  memcpy (tmp + blen, in, inlen);

  switch (algo)
    {
    case SHISHI_DES_CBC_CRC:
      rc = shishi_crc (handle, tmp, tmplen, &p);
      break;

    case SHISHI_DES_CBC_MD4:
      rc = shishi_md4 (handle, tmp, tmplen, &p);
      break;

    case SHISHI_DES_CBC_MD5:
      rc = shishi_md5 (handle, tmp, tmplen, &p);
      break;

    default:
      shishi_error_printf (handle, "MD %d unknown in raw des checksum", algo);
      return SHISHI_CRYPTO_INTERNAL_ERROR;
      break;
    }

  memcpy (out + blen, p, hlen);

  *outlen = blen + hlen;

  return SHISHI_OK;
}

static int
raw_des_checksum1 (Shishi * handle, int algo,
		   const char *in, size_t inlen, char *out, size_t * outlen)
{
  char *tmp;
  size_t tmplen;
  char *p;
  int blen = 8;
  int hlen = (algo == SHISHI_DES_CBC_CRC) ? 4 : 16;
  int rc;

  rc = shishi_randomize (handle, 0, out, blen);
  if (rc != SHISHI_OK)
    return rc;

  memset (out + blen, 0, hlen);

  tmplen = blen + hlen + inlen;
  tmp = xmalloc (tmplen);

  memcpy (tmp, out, blen + hlen);
  memcpy (tmp + blen + hlen, in, inlen);

  switch (algo)
    {
    case SHISHI_DES_CBC_CRC:
      rc = shishi_crc (handle, tmp, tmplen, &p);
      break;

    case SHISHI_DES_CBC_MD4:
      rc = shishi_md4 (handle, tmp, tmplen, &p);
      break;

    case SHISHI_DES_CBC_MD5:
      rc = shishi_md5 (handle, tmp, tmplen, &p);
      break;

    default:
      shishi_error_printf (handle, "MD %d unknown in raw des checksum", algo);
      return SHISHI_CRYPTO_INTERNAL_ERROR;
      break;
    }

  free (tmp);

  memcpy (out + blen, p, hlen);

  free (p);

  *outlen = blen + hlen;

  return SHISHI_OK;
}

static int
des_encrypt_checksum (Shishi * handle,
		      Shishi_key * key,
		      int keyusage,
		      const char *iv, size_t ivlen,
		      char **ivout, size_t * ivoutlen,
		      const char *in, size_t inlen,
		      char **out, size_t * outlen, int algo)
{
  char cksum[8 + MAX_HASH_LEN];
  char *inpad;
  char *pt;
  size_t inpadlen, padzerolen = 0, ptlen, cksumlen;
  int hlen = (algo == SHISHI_DES_CBC_CRC) ? 4 : 16;
  int res;

  if ((inlen + hlen) % 8)
    padzerolen = 8 - ((inlen + hlen) % 8);
  inpadlen = inlen + padzerolen;
  inpad = xmalloc (inpadlen);

  memcpy (inpad, in, inlen);
  memset (inpad + inlen, 0, padzerolen);

  res = raw_des_checksum1 (handle, algo, inpad, inpadlen, cksum, &cksumlen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "DES checksum failed");
      return res;
    }

  ptlen = inpadlen + cksumlen;
  pt = xmalloc (ptlen);
  memcpy (pt, cksum, cksumlen);
  memcpy (pt + cksumlen, inpad, inpadlen);

  free (inpad);

  res = _shishi_simplified_encrypt (handle, key, 0, iv, ivlen,
				    ivout, ivoutlen, pt, ptlen, out, outlen);

  free (pt);

  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "DES encrypt failed");
      return res;
    }

  return SHISHI_OK;
}

static int
des_crc_encrypt (Shishi * handle,
		 Shishi_key * key,
		 int keyusage,
		 const char *iv, size_t ivlen,
		 char **ivout, size_t * ivoutlen,
		 const char *in, size_t inlen, char **out, size_t * outlen)
{
  return des_encrypt_checksum (handle, key, keyusage,
			       shishi_key_value (key),
			       shishi_key_length (key), ivout, ivoutlen, in,
			       inlen, out, outlen, SHISHI_DES_CBC_CRC);
}

static int
des_md4_encrypt (Shishi * handle,
		 Shishi_key * key,
		 int keyusage,
		 const char *iv,
		 size_t ivlen,
		 char **ivout, size_t * ivoutlen,
		 const char *in, size_t inlen, char **out, size_t * outlen)
{
  return des_encrypt_checksum (handle, key, keyusage, iv, ivlen, ivout,
			       ivoutlen, in, inlen, out, outlen,
			       SHISHI_DES_CBC_MD4);
}

static int
des_md5_encrypt (Shishi * handle,
		 Shishi_key * key,
		 int keyusage,
		 const char *iv,
		 size_t ivlen,
		 char **ivout, size_t * ivoutlen,
		 const char *in, size_t inlen, char **out, size_t * outlen)
{
  return des_encrypt_checksum (handle, key, keyusage, iv, ivlen, ivout,
			       ivoutlen, in, inlen, out, outlen,
			       SHISHI_DES_CBC_MD5);
}

static int
des_none_encrypt (Shishi * handle,
		  Shishi_key * key,
		  int keyusage,
		  const char *iv,
		  size_t ivlen,
		  char **ivout, size_t * ivoutlen,
		  const char *in, size_t inlen, char **out, size_t * outlen)
{
  return _shishi_simplified_encrypt (handle, key, 0, iv, ivlen, ivout,
				     ivoutlen, in, inlen, out, outlen);
}

static int
des_decrypt_verify (Shishi * handle,
		    Shishi_key * key,
		    int keyusage,
		    const char *iv, size_t ivlen,
		    char **ivout, size_t * ivoutlen,
		    const char *in, size_t inlen,
		    char **out, size_t * outlen, int algo)
{
  int res;
  char incoming[16];
  char *computed;
  size_t hlen = (algo == SHISHI_DES_CBC_CRC) ? 4 : 16;

  res = _shishi_simplified_decrypt (handle, key, 0, iv, ivlen,
				    ivout, ivoutlen, in, inlen, out, outlen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "decrypt failed");
      return res;
    }

  if (VERBOSECRYPTONOISE (handle))
    {
      puts ("verify decrypted:");
      _shishi_escapeprint (*out, *outlen);
      _shishi_hexprint (*out, *outlen);
    }

  memcpy (incoming, *out + 8, hlen);
  memset (*out + 8, 0, hlen);

  if (VERBOSECRYPTONOISE (handle))
    {
      puts ("cksum pt:");
      _shishi_hexprint (*out, *outlen);
    }

  switch (algo)
    {
    case SHISHI_DES_CBC_CRC:
      shishi_crc (handle, *out, *outlen, &computed);
      break;

    case SHISHI_DES_CBC_MD4:
      shishi_md4 (handle, *out, *outlen, &computed);
      break;

    case SHISHI_DES_CBC_MD5:
      shishi_md5 (handle, *out, *outlen, &computed);
      break;

    default:
      shishi_error_printf (handle, "MD %d unknown in raw des verify", algo);
      return SHISHI_CRYPTO_ERROR;
      break;
    }

  if (VERBOSECRYPTONOISE (handle))
    {
      puts ("DES verify:");
      _shishi_hexprint (incoming, hlen);
      _shishi_hexprint (computed, hlen);
    }

  if (memcmp (computed, incoming, hlen) != 0)
    {
      shishi_error_printf (handle, "DES hash verify failed");
      return SHISHI_CRYPTO_ERROR;
    }

  free (computed);

  memmove (*out, *out + 8 + hlen, *outlen - 8 - hlen);
  *outlen -= 8 + hlen;

  return SHISHI_OK;
}

static int
des_crc_decrypt (Shishi * handle,
		 Shishi_key * key,
		 int keyusage,
		 const char *iv,
		 size_t ivlen,
		 char **ivout, size_t * ivoutlen,
		 const char *in, size_t inlen, char **out, size_t * outlen)
{
  return des_decrypt_verify (handle, key, keyusage,
			     shishi_key_value (key), shishi_key_length (key),
			     ivout, ivoutlen, in, inlen, out, outlen,
			     SHISHI_DES_CBC_CRC);
}

static int
des_md4_decrypt (Shishi * handle,
		 Shishi_key * key,
		 int keyusage,
		 const char *iv,
		 size_t ivlen,
		 char **ivout, size_t * ivoutlen,
		 const char *in, size_t inlen, char **out, size_t * outlen)
{
  return des_decrypt_verify (handle, key, keyusage, iv, ivlen, ivout,
			     ivoutlen, in, inlen, out, outlen,
			     SHISHI_DES_CBC_MD4);
}

static int
des_md5_decrypt (Shishi * handle,
		 Shishi_key * key,
		 int keyusage,
		 const char *iv,
		 size_t ivlen,
		 char **ivout, size_t * ivoutlen,
		 const char *in, size_t inlen, char **out, size_t * outlen)
{
  return des_decrypt_verify (handle, key, keyusage, iv, ivlen, ivout,
			     ivoutlen, in, inlen, out, outlen,
			     SHISHI_DES_CBC_MD5);
}

static int
des_none_decrypt (Shishi * handle,
		  Shishi_key * key,
		  int keyusage,
		  const char *iv,
		  size_t ivlen,
		  char **ivout, size_t * ivoutlen,
		  const char *in, size_t inlen, char **out, size_t * outlen)
{
  return _shishi_simplified_decrypt (handle, key, 0, iv, ivlen, ivout,
				     ivoutlen, in, inlen, out, outlen);
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

static char weak_des_keys[16][8] = {
  /* Weak keys */
  "\x01\x01\x01\x01\x01\x01\x01\x01",
  "\x1F\x1F\x1F\x1F\x0E\x0E\x0E\x0E",
  "\xE0\xE0\xE0\xE0\xF1\xF1\xF1\xF1",
  "\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE",
  /* Semiweak keys */
  "\x01\xFE\x01\xFE\x01\xFE\x01\xFE",
  "\x1F\xE0\x1F\xE0\x0E\xF1\x0E\xF1",
  "\x01\xE0\x01\xE0\x01\xF1\x01\xF1",
  "\x1F\xFE\x1F\xFE\x0E\xFE\x0E\xFE",
  "\x01\x1F\x01\x1F\x01\x0E\x01\x0E",
  "\xE0\xFE\xE0\xFE\xF1\xFE\xF1\xFE",
  "\xFE\x01\xFE\x01\xFE\x01\xFE\x01",
  "\xE0\x1F\xE1\x0F\xF1\x0E\xF1\x0E",
  "\xE0\x01\xE0\x01\xF1\x01\xF1\x01",
  "\xFE\x1F\xFE\x1F\xFE\x0E\xFE\x0E",
  "\x1F\x01\x1F\x01\x0E\x01\x0E\x01",
  "\xFE\xE0\xFE\xE0\xFE\xF1\xFE\xF1"
};

static void
des_key_correction (Shishi * handle, char key[8])
{
  size_t i;

  /* fixparity(key); */
  des_set_odd_key_parity (key);

  /* This loop could be replaced by optimized code (compare nettle),
     but let's not do that. */
  for (i = 0; i < 16; i++)
    if (memcmp (key, weak_des_keys[i], 8) == 0)
      {
	if (VERBOSECRYPTONOISE (handle))
	  printf ("\t ;; WEAK KEY (corrected)\n");
	key[7] ^= 0xF0;
	break;
      }
}

static int
des_random_to_key (Shishi * handle,
		   const char *rnd, size_t rndlen, Shishi_key * outkey)
{
  char tmp[MAX_RANDOM_LEN];
  int keylen = shishi_cipher_keylen (shishi_key_type (outkey));

  if (rndlen != shishi_key_length (outkey))
    {
      shishi_error_printf (handle, "DES random to key caller error");
      return SHISHI_CRYPTO_ERROR;
    }

  memcpy (tmp, rnd, keylen);
  des_set_odd_key_parity (tmp);

  shishi_key_value_set (outkey, tmp);

  return SHISHI_OK;
}

static int
des_string_to_key (Shishi * handle,
		   const char *string,
		   size_t stringlen,
		   const char *salt,
		   size_t saltlen, const char *parameter, Shishi_key * outkey)
{
  char *s;
  int n_s;
  int odd;
  char tempkey[8];
  char *p;
  int i, j;
  char temp, temp2;
  int res;

  if (VERBOSECRYPTO (handle))
    {
      printf ("des_string_to_key (string, salt)\n");
      printf ("\t ;; String:\n");
      _shishi_escapeprint (string, stringlen);
      _shishi_hexprint (string, stringlen);
      printf ("\t ;; Salt:\n");
      _shishi_escapeprint (salt, saltlen);
      _shishi_hexprint (salt, saltlen);
    }

  if (VERBOSECRYPTONOISE (handle))
    {
      printf ("odd = 1;\n");
      printf ("s = string | salt;\n");
      printf ("tempstring = 0; /* 56-bit string */\n");
      printf ("pad(s); /* with nulls to 8 byte boundary */\n");

    }

  odd = 1;
  n_s = stringlen + saltlen;
  if ((n_s % 8) != 0)
    n_s += 8 - n_s % 8;
  s = (char *) xmalloc (n_s);
  memcpy (s, string, stringlen);
  if (saltlen > 0)
    memcpy (s + stringlen, salt, saltlen);
  memset (s + stringlen + saltlen, 0, n_s - stringlen - saltlen);
  memset (tempkey, 0, sizeof (tempkey));	/* tempkey = NULL; */

  if (VERBOSECRYPTONOISE (handle))
    {
      printf ("\t ;; s = pad(string|salt):\n");
      _shishi_escapeprint (s, n_s);
      _shishi_hexprint (s, n_s);
    }

  for (i = 0; i < n_s / 8; i++)
    {
      if (VERBOSECRYPTONOISE (handle))
	{
	  printf ("for (8byteblock in s) {\n");
	  printf ("\t ;; loop iteration %d\n", i);
	  printf ("\t ;; 8byteblock:\n");
	  _shishi_escapeprint (&s[i * 8], 8);
	  _shishi_hexprint (&s[i * 8], 8);
	  _shishi_binprint (&s[i * 8], 8);
	  printf ("56bitstring = removeMSBits(8byteblock);\n");
	}

      for (j = 0; j < 8; j++)
	s[i * 8 + j] = s[i * 8 + j] & ~0x80;

      if (VERBOSECRYPTONOISE (handle))
	{
	  printf ("\t ;; 56bitstring:\n");
	  _shishi_bin7print (&s[i * 8], 8);
	  printf ("if (odd == 0) reverse(56bitstring);\t ;; odd=%d\n", odd);
	}

      if (odd == 0)
	{
	  for (j = 0; j < 4; j++)
	    {
	      temp = s[i * 8 + j];
	      temp =
		((temp >> 6) & 0x01) |
		((temp >> 4) & 0x02) |
		((temp >> 2) & 0x04) |
		((temp) & 0x08) |
		((temp << 2) & 0x10) |
		((temp << 4) & 0x20) | ((temp << 6) & 0x40);
	      temp2 = s[i * 8 + 7 - j];
	      temp2 =
		((temp2 >> 6) & 0x01) |
		((temp2 >> 4) & 0x02) |
		((temp2 >> 2) & 0x04) |
		((temp2) & 0x08) |
		((temp2 << 2) & 0x10) |
		((temp2 << 4) & 0x20) | ((temp2 << 6) & 0x40);
	      s[i * 8 + j] = temp2;
	      s[i * 8 + 7 - j] = temp;
	    }
	  if (VERBOSECRYPTONOISE (handle))
	    {
	      printf ("reverse(56bitstring)\n");
	      printf ("\t ;; 56bitstring after reverse\n");
	      _shishi_bin7print (&s[i * 8], 8);
	    }
	}

      odd = !odd;

      if (VERBOSECRYPTONOISE (handle))
	{
	  printf ("odd = ! odd\n");
	  printf ("tempstring = tempstring XOR 56bitstring;\n");
	}

      /* tempkey = tempkey XOR 8byteblock; */
      for (j = 0; j < 8; j++)
	tempkey[j] ^= s[i * 8 + j];

      if (VERBOSECRYPTONOISE (handle))
	{
	  printf ("\t ;; tempstring\n");
	  _shishi_bin7print (tempkey, 8);
	}
    }

  for (j = 0; j < 8; j++)
    tempkey[j] = tempkey[j] << 1;

  if (VERBOSECRYPTONOISE (handle))
    {
      printf ("for (8byteblock in s) {\n");
      printf ("}\n");
      printf ("\t ;; for loop terminated\n");
      printf ("\t ;; tempstring as 64bitblock\n");
      _shishi_hexprint (tempkey, 8);
      _shishi_binprint (tempkey, 8);
      printf ("/* add parity as low bit of each byte */\n");
      printf ("tempkey = key_correction(add_parity_bits(tempstring));\n");
    }

  des_key_correction (handle, tempkey);

  if (VERBOSECRYPTONOISE (handle))
    {
      printf ("\t ;; tempkey\n");
      _shishi_escapeprint (tempkey, 8);
      _shishi_hexprint (tempkey, 8);
      _shishi_binprint (tempkey, 8);
      printf ("key = key_correction(DES-CBC-check(s,tempkey));\n");
    }

  memcpy (s, string, stringlen);
  if (saltlen > 0)
    memcpy (s + stringlen, salt, saltlen);
  memset (s + stringlen + saltlen, 0, n_s - stringlen - saltlen);

  res = shishi_des_cbc_mac (handle, tempkey, tempkey, s, n_s, &p);
  if (res != SHISHI_OK)
    return res;
  free (s);
  memcpy (tempkey, p, 8);
  free (p);

  des_key_correction (handle, tempkey);

  if (VERBOSECRYPTO (handle))
    {
      printf ("\t ;; key\n");
      _shishi_escapeprint (tempkey, 8);
      _shishi_hexprint (tempkey, 8);
      _shishi_binprint (tempkey, 8);
    }

  shishi_key_value_set (outkey, tempkey);

  return SHISHI_OK;
}

static int
des_checksum (Shishi * handle,
	      Shishi_key * key,
	      int keyusage,
	      int cksumtype,
	      const char *in, size_t inlen,
	      char **out, size_t * outlen, int algo)
{
  char cksum[8 + MAX_HASH_LEN];
  size_t cksumlen;
  char *keyp;
  int i;
  int res;

  res = raw_des_checksum0 (handle, algo, in, inlen, cksum, &cksumlen);
  if (res != SHISHI_OK)
    {
      shishi_error_set (handle, "raw des checksum failed");
      return res;
    }

  keyp = (char*) shishi_key_value (key);

  for (i = 0; i < 8; i++)
    keyp[i] ^= 0xF0;

  res = _shishi_simplified_dencrypt (handle, key, NULL, 0, NULL, NULL,
				     cksum, cksumlen, out, outlen, 0);

  for (i = 0; i < 8; i++)
    keyp[i] ^= 0xF0;

  if (res != SHISHI_OK)
    {
      shishi_error_set (handle, "encrypt failed");
      return res;
    }

  return SHISHI_OK;
}

static int
des_crc_checksum (Shishi * handle,
		  Shishi_key * key,
		  int keyusage,
		  int cksumtype,
		  const char *in, size_t inlen, char **out, size_t * outlen)
{
  return des_checksum (handle, key, keyusage, cksumtype,
		       in, inlen, out, outlen, SHISHI_DES_CBC_CRC);
}

static int
des_md4_checksum (Shishi * handle,
		  Shishi_key * key,
		  int keyusage,
		  int cksumtype,
		  const char *in, size_t inlen, char **out, size_t * outlen)
{
  return des_checksum (handle, key, keyusage, cksumtype,
		       in, inlen, out, outlen, SHISHI_DES_CBC_MD4);
}

static int
des_md5_checksum (Shishi * handle,
		  Shishi_key * key,
		  int keyusage,
		  int cksumtype,
		  const char *in, size_t inlen, char **out, size_t * outlen)
{
  return des_checksum (handle, key, keyusage, cksumtype,
		       in, inlen, out, outlen, SHISHI_DES_CBC_MD5);
}

static int
gss_des_checksum (Shishi * handle,
		  Shishi_key * key,
		  int keyusage,
		  int cksumtype,
		  const char *in, size_t inlen, char **out, size_t * outlen)
{
  char *p;
  int rc;

  rc = shishi_md5 (handle, in, inlen, &p);
  if (rc != SHISHI_OK)
    return rc;

  *outlen = 8;
  rc = shishi_des_cbc_mac (handle, shishi_key_value (key), NULL, p, 16, out);

  free (p);

  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

static int
des_verify (Shishi * handle, int algo,
	    Shishi_key * key,
	    const char *in, size_t inlen, const char *cksum, size_t cksumlen)
{
  char *out;
  size_t outlen;
  char *md;
  size_t tmplen;
  char *tmp;
  char *keyp;
  size_t i;
  int res;

  if (cksumlen != 8 + 16)
    return SHISHI_VERIFY_FAILED;

  /*
   * get_mic                   des-cbc(key XOR 0xF0F0F0F0F0F0F0F0,
   *                                   conf | rsa-md5(conf | msg))
   * verify_mic                decrypt and verify rsa-md5 checksum
   */

  keyp = (char*) shishi_key_value (key);

  for (i = 0; i < 8; i++)
    keyp[i] ^= 0xF0;

  res = _shishi_simplified_decrypt (handle, key, 0, NULL, 0, NULL, NULL,
				    cksum, cksumlen, &out, &outlen);

  for (i = 0; i < 8; i++)
    keyp[i] ^= 0xF0;

  if (res != SHISHI_OK)
    {
      shishi_error_set (handle, "decrypt failed");
      return res;
    }

  tmplen = 8 + inlen;
  tmp = xmalloc (tmplen);
  memcpy (tmp, out, 8);
  memcpy (tmp + 8, in, inlen);

  switch (algo)
    {
    case SHISHI_RSA_MD4_DES:
      res = shishi_md4 (handle, tmp, tmplen, &md);
      break;

    case SHISHI_RSA_MD5_DES:
      res = shishi_md5 (handle, tmp, tmplen, &md);
      break;

    default:
      res = SHISHI_CRYPTO_ERROR;
    }

  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "DES verify MD error");
      return res;
    }

  if (memcmp (out + 8, md, 16) != 0)
    return SHISHI_VERIFY_FAILED;

  return SHISHI_OK;
}

static int
des_md4_verify (Shishi * handle,
		Shishi_key * key,
		int keyusage,
		int cksumtype,
		const char *in, size_t inlen,
		const char *cksum, size_t cksumlen)
{
  return des_verify (handle, SHISHI_RSA_MD4_DES, key,
		     in, inlen, cksum, cksumlen);
}

static int
des_md5_verify (Shishi * handle,
		Shishi_key * key,
		int keyusage,
		int cksumtype,
		const char *in, size_t inlen,
		const char *cksum, size_t cksumlen)
{
  return des_verify (handle, SHISHI_RSA_MD5_DES, key,
		     in, inlen, cksum, cksumlen);
}

cipherinfo des_cbc_crc_info = {
  SHISHI_DES_CBC_CRC,
  "des-cbc-crc",
  8,
  8,
  8,
  8,
  SHISHI_CRC32,
  des_random_to_key,
  des_string_to_key,
  des_crc_encrypt,
  des_crc_decrypt
};

cipherinfo des_cbc_md4_info = {
  SHISHI_DES_CBC_MD4,
  "des-cbc-md4",
  8,
  8,
  8,
  8,
  SHISHI_RSA_MD4_DES,
  des_random_to_key,
  des_string_to_key,
  des_md4_encrypt,
  des_md4_decrypt
};

cipherinfo des_cbc_md5_info = {
  SHISHI_DES_CBC_MD5,
  "des-cbc-md5",
  8,
  8,
  8,
  8,
  SHISHI_RSA_MD5_DES,
  des_random_to_key,
  des_string_to_key,
  des_md5_encrypt,
  des_md5_decrypt
};

cipherinfo des_cbc_none_info = {
  SHISHI_DES_CBC_NONE,
  "des-cbc-none",
  8,
  8,
  8,
  8,
  SHISHI_RSA_MD5_DES,
  des_random_to_key,
  des_string_to_key,
  des_none_encrypt,
  des_none_decrypt
};

checksuminfo crc32_info = {
  SHISHI_CRC32,
  "crc32",
  4,
  des_crc_checksum,
  NULL
};

checksuminfo md4_des_info = {
  SHISHI_RSA_MD4_DES,
  "rsa-md4-des",
  24,
  des_md4_checksum,
  des_md4_verify
};

checksuminfo md5_des_info = {
  SHISHI_RSA_MD5_DES,
  "rsa-md5-des",
  24,
  des_md5_checksum,
  des_md5_verify
};

checksuminfo md5_gss_info = {
  SHISHI_RSA_MD5_DES_GSS,
  "rsa-md5-des-gss",
  8,
  gss_des_checksum,
  NULL
};
