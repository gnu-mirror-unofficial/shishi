/* crypto-des.c	DES crypto functions
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
raw_des_checksum0 (Shishi * handle, int algo,
		   const char *in, size_t inlen,
		   char *out, size_t * outlen)
{
  char *tmp;
  size_t tmplen;
  char *p;
  size_t plen;
  int blen = 8;
  int hlen = 16;
  int rc;

  rc = shishi_randomize (handle, out, blen);
  if (rc != SHISHI_OK)
    return rc;

  tmplen = blen + inlen;
  tmp = xmalloc (tmplen);

  memcpy (tmp, out, blen);
  memcpy (tmp + blen, in, inlen);

  switch (algo)
    {
    case SHISHI_DES_CBC_MD4:
      rc = shishi_md4 (handle, tmp, tmplen, &p, &plen);
      break;

    case SHISHI_DES_CBC_MD5:
      rc = shishi_md5 (handle, tmp, tmplen, &p, &plen);
      break;

    default:
      shishi_error_printf (handle, "MD %d unknown in raw des checksum", algo);
      return SHISHI_CRYPTO_INTERNAL_ERROR;
      break;
    }

  memcpy (out + blen, p, plen);

  *outlen = blen + hlen;

  return SHISHI_OK;
}

static int
raw_des_checksum1 (Shishi * handle, int algo,
		   const char *in, size_t inlen,
		   char *out, size_t * outlen)
{
  char *tmp;
  size_t tmplen;
  char *p;
  size_t plen;
  int blen = 8;
  int hlen = 16;
  int rc;

  rc = shishi_randomize (handle, out, blen);
  if (rc != SHISHI_OK)
    return rc;

  memset (out + blen, 0, hlen);

  tmplen = blen + hlen + inlen;
  tmp = xmalloc (tmplen);

  memcpy (tmp, out, blen + hlen);
  memcpy (tmp + blen + hlen, in, inlen);

  switch (algo)
    {
    case SHISHI_DES_CBC_MD4:
      rc = shishi_md4 (handle, tmp, tmplen, &p, &plen);
      break;

    case SHISHI_DES_CBC_MD5:
      rc = shishi_md5 (handle, tmp, tmplen, &p, &plen);
      break;

    default:
      shishi_error_printf (handle, "MD %d unknown in raw des checksum", algo);
      return SHISHI_CRYPTO_INTERNAL_ERROR;
      break;
    }

  memcpy (out + blen, p, plen);

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
  int res;

  if (inlen % 8)
    padzerolen = 8 - (inlen % 8);
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

  res = simplified_encrypt (handle, key, 0, iv, ivlen, ivout, ivoutlen,
			    pt, ptlen, out, outlen);

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
  return des_encrypt_checksum (handle, key, keyusage, iv, ivlen, ivout,
			       ivoutlen, in, inlen, out, outlen,
			       SHISHI_DES_CBC_CRC);
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
  return simplified_encrypt (handle, key, 0, iv, ivlen, ivout, ivoutlen,
			     in, inlen, out, outlen);
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
  size_t hlen = 16;

  res = simplified_decrypt (handle, key, 0, iv, ivlen, ivout, ivoutlen,
			    in, inlen, out, outlen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "decrypt failed");
      return res;
    }

  memcpy (incoming, *out + 8, hlen);
  memset (*out + 8, 0, hlen);

  switch (algo)
    {
    case SHISHI_DES_CBC_MD4:
      shishi_md4 (handle, *out, *outlen, &computed, &hlen);
      break;

    case SHISHI_DES_CBC_MD5:
      shishi_md5 (handle, *out, *outlen, &computed, &hlen);
      break;

    default:
      shishi_error_printf (handle, "MD %d unknown in raw des verify", algo);
      return SHISHI_CRYPTO_ERROR;
      break;
    }

  if (VERBOSECRYPTO (handle))
    {
      puts ("DES verify:");
      hexprint (incoming, hlen);
      puts ("");
      hexprint (computed, hlen);
      puts ("");
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
  return des_decrypt_verify (handle, key, keyusage, iv, ivlen, ivout,
			     ivoutlen, in, inlen, out, outlen,
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
  return simplified_decrypt (handle, key, 0, iv, ivlen, ivout, ivoutlen,
			     in, inlen, out, outlen);
}

static int
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

  return SHISHI_OK;
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

static int
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
	if (VERBOSECRYPTO (handle))
	  printf ("\t ;; WEAK KEY (corrected)\n");
	key[7] ^= 0xF0;
	break;
      }

  return SHISHI_OK;
}

static int
des_random_to_key (Shishi * handle,
		   const char *random, size_t randomlen, Shishi_key * outkey)
{
  char tmp[MAX_RANDOM_LEN];
  int keylen = shishi_cipher_keylen (shishi_key_type (outkey));

  if (randomlen != shishi_key_length (outkey))
    {
      shishi_error_printf (handle, "DES random to key caller error");
      return SHISHI_CRYPTO_ERROR;
    }

  memcpy (tmp, random, keylen);
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
      escapeprint (string, stringlen);
      hexprint (string, stringlen);
      puts ("");
      puts ("");

      printf ("\t ;; Salt:\n");
      escapeprint (salt, saltlen);
      hexprint (salt, saltlen);
      puts ("");

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

  if (VERBOSECRYPTO (handle))
    {
      printf ("\t ;; s = pad(string|salt):\n");
      escapeprint (s, n_s);
      hexprint (s, n_s);
      puts ("");
    }

  for (i = 0; i < n_s / 8; i++)
    {
      if (VERBOSECRYPTO (handle))
	{
	  printf ("for (8byteblock in s) {\n");
	  printf ("\t ;; loop iteration %d\n", i);
	  printf ("\t ;; 8byteblock:\n");
	  escapeprint (&s[i * 8], 8);
	  hexprint (&s[i * 8], 8);
	  puts ("");
	  binprint (&s[i * 8], 8);
	  puts ("");
	  printf ("56bitstring = removeMSBits(8byteblock);\n");
	}

      for (j = 0; j < 8; j++)
	s[i * 8 + j] = s[i * 8 + j] & ~0x80;

      if (VERBOSECRYPTO (handle))
	{
	  printf ("\t ;; 56bitstring:\n");
	  bin7print (&s[i * 8], 8);
	  puts ("");
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
	  if (VERBOSECRYPTO (handle))
	    {
	      printf ("reverse(56bitstring)\n");
	      printf ("\t ;; 56bitstring after reverse\n");
	      bin7print (&s[i * 8], 8);
	      puts ("");
	    }
	}

      odd = !odd;

      if (VERBOSECRYPTO (handle))
	{
	  printf ("odd = ! odd\n");
	  printf ("tempstring = tempstring XOR 56bitstring;\n");
	}

      /* tempkey = tempkey XOR 8byteblock; */
      for (j = 0; j < 8; j++)
	tempkey[j] ^= s[i * 8 + j];

      if (VERBOSECRYPTO (handle))
	{
	  printf ("\t ;; tempstring\n");
	  bin7print (tempkey, 8);
	  puts ("");
	  puts ("");
	}
    }

  for (j = 0; j < 8; j++)
    tempkey[j] = tempkey[j] << 1;

  if (VERBOSECRYPTO (handle))
    {
      printf ("for (8byteblock in s) {\n");
      printf ("}\n");
      printf ("\t ;; for loop terminated\n");
      printf ("\t ;; tempstring as 64bitblock\n");
      hexprint (tempkey, 8);
      puts ("");
      binprint (tempkey, 8);
      puts ("");
      printf ("/* add parity as low bit of each byte */\n");
      printf ("tempkey = key_correction(add_parity_bits(tempstring));\n");
    }

  res = des_key_correction (handle, tempkey);
  if (res != SHISHI_OK)
    return res;

  if (VERBOSECRYPTO (handle))
    {
      printf ("\t ;; tempkey\n");
      escapeprint (tempkey, 8);
      hexprint (tempkey, 8);
      puts ("");
      binprint (tempkey, 8);
      puts ("");
      puts ("");
      printf ("key = key_correction(DES-CBC-check(s,tempkey));\n");
    }

  memcpy (s, string, stringlen);
  if (saltlen > 0)
    memcpy (s + stringlen, salt, saltlen);
  memset (s + stringlen + saltlen, 0, n_s - stringlen - saltlen);

  res = shishi_des_cbc_mac (handle, tempkey, tempkey, s, n_s, &p);
  if (res != SHISHI_OK)
    return res;
  memcpy (tempkey, p, 8);
  free (p);

  res = des_key_correction (handle, tempkey);
  if (res != SHISHI_OK)
    return res;

  if (VERBOSECRYPTO (handle))
    {
      printf ("\t ;; key\n");
      escapeprint (tempkey, 8);
      hexprint (tempkey, 8);
      puts ("");
      binprint (tempkey, 8);
      puts ("");
      puts ("");
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

  keyp = shishi_key_value (key);

  for (i = 0; i < 8; i++)
    keyp[i] ^= 0xF0;

  res = simplified_dencrypt (handle, key, NULL, 0, NULL, NULL,
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
  size_t plen;
  int rc;

  rc = shishi_md5 (handle, in, inlen, &p, &plen);
  if (rc != SHISHI_OK)
    return rc;

  *outlen = 8;
  rc = shishi_des_cbc_mac (handle, shishi_key_value (key), NULL, p, plen, out);

  free (p);

  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

static int
des_verify (Shishi * handle, int algo,
	    const char key[8],
	    const char *in, size_t inlen,
	    const char *cksum, size_t cksumlen)
{
  char *out;
  size_t outlen;
  char *md;
  size_t mdlen;
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

  keyp = xmemdup (key, 8);
  for (i = 0; i < 8; i++)
    keyp[i] ^= 0xF0;

  res = simplified_decrypt (handle, key, 0, NULL, 0, NULL, NULL,
			    cksum, cksumlen, &out, &outlen);

  free (keyp);

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
      res = shishi_md4 (handle, tmp, tmplen, &md, &mdlen);
      break;

    case SHISHI_RSA_MD5_DES:
      res = shishi_md5 (handle, tmp, tmplen, &md, &mdlen);
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
  return des_verify (handle, SHISHI_RSA_MD4_DES, shishi_key_value (key),
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
  return des_verify (handle, SHISHI_RSA_MD5_DES, shishi_key_value (key),
		     in, inlen, cksum, cksumlen);
}
