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
raw_des_verify (Shishi * handle, int algo, char *out, int *outlen)
{
#ifdef USE_GCRYPT
  char md[MAX_HASH_LEN];
  gcry_md_hd_t hd;
  gpg_error_t err;
  int alg = (algo == SHISHI_DES_CBC_MD4) ? GCRY_MD_MD4 : GCRY_MD_MD5;
  int hlen = gcry_md_get_algo_dlen (alg);
  int ok;
  char *p;

  memcpy (md, out + 8, hlen);
  memset (out + 8, 0, hlen);

  err = gcry_md_open (&hd, alg, 0);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "Algo %d not available in libgcrypt", alg);
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  gcry_md_write (hd, out, *outlen);

  p = gcry_md_read (hd, alg);
  if (p == NULL)
    {
      shishi_error_printf (handle, "Libgcrypt failed to compute hash");
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  if (VERBOSECRYPTO (handle))
    {
      puts("DES verify:");
      hexprint(md, hlen); puts("");
      hexprint (p, hlen); puts("");
    }

  ok = memcmp (p, md, hlen) == 0;

  gcry_md_close (hd);

  if (!ok)
    {
      shishi_error_printf (handle, "DES verify failed");
      return SHISHI_CRYPTO_ERROR;
    }

  memmove (out, out + 8 + hlen, *outlen - 8 - hlen);
  *outlen -= 8 + hlen;
#else
  struct md5_ctx md5;
  struct md4_ctx md4;
  char incoming[MAX_HASH_LEN];
  char computed[MAX_HASH_LEN];
  int hlen;
  int rc;

  switch (algo)
    {
    case SHISHI_DES_CBC_MD4:
      memcpy (incoming, out + 8, MD4_DIGEST_SIZE);
      memset (out + 8, 0, MD4_DIGEST_SIZE);
      md4_init (&md4);
      md4_update (&md4, *outlen, out);
      md4_digest (&md4, MD4_DIGEST_SIZE, computed);
      hlen = MD4_DIGEST_SIZE;
      break;

    case SHISHI_DES_CBC_MD5:
      memcpy (incoming, out + 8, MD5_DIGEST_SIZE);
      memset (out + 8, 0, MD5_DIGEST_SIZE);
      md5_init (&md5);
      md5_update (&md5, *outlen, out);
      md5_digest (&md5, MD5_DIGEST_SIZE, computed);
      hlen = MD5_DIGEST_SIZE;
      break;
    }

  if (VERBOSECRYPTO (handle))
    {
      puts("DES verify:");
      hexprint(incoming, hlen); puts("");
      hexprint (computed, hlen); puts("");
    }

  if (memcmp (computed, incoming, hlen) != 0)
    {
      shishi_error_printf (handle, "DES hash verify failed");
      return SHISHI_CRYPTO_ERROR;
    }

  memmove (out, out + 8 + hlen, *outlen - 8 - hlen);
  *outlen -= 8 + hlen;
#endif

  return SHISHI_OK;
}

static int
raw_des_checksum (Shishi * handle,
		  int algo,
		  const char *in, size_t inlen,
		  char *out, size_t * outlen,
		  int hashzeros)
{
#ifdef USE_GCRYPT
  gpg_error_t err;
  int alg = (alg == SHISHI_DES_CBC_MD4) ? GCRY_MD_MD4 : GCRY_MD_MD5;
  int hlen = gcry_md_get_algo_dlen (alg);
  char buffer[8 + MAX_HASH_LEN];
  char *p;
  gcry_md_hd_t hd;
  int res;

  err = gcry_md_open (&hd, alg, 0);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "MD %d not available in libgcrypt", alg);
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  res = shishi_randomize (handle, buffer, 8);
  if (res != SHISHI_OK)
    return res;

  memset (buffer + 8, 0, hlen);

  if (hashzeros)
    gcry_md_write (hd, buffer, 8 + hlen);
  else
    gcry_md_write (hd, buffer, 8);
  gcry_md_write (hd, in, inlen);

  p = gcry_md_read (hd, alg);
  if (p == NULL)
    {
      shishi_error_printf (handle, "Libgcrypt failed to compute hash");
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  memcpy(out, buffer, 8);
  memcpy(out + 8, p, hlen);

  gcry_md_close (hd);

  *outlen = 8 + hlen;
#else
  struct md5_ctx md5;
  struct md4_ctx md4;
  int hlen;
  int rc;

  rc = shishi_randomize (handle, out, 8);
  if (rc != SHISHI_OK)
    return rc;

  switch (algo)
    {
    case SHISHI_DES_CBC_MD4:
      memset (out + 8, 0, MD4_DIGEST_SIZE);
      md4_init (&md4);
      if (hashzeros)
	md4_update (&md4, 8 + MD4_DIGEST_SIZE, out);
      else
	md4_update (&md4, 8, out);
      md4_update (&md4, inlen, in);

      md4_digest (&md4, MD4_DIGEST_SIZE, out + 8);

      hlen = MD4_DIGEST_SIZE;
      break;

    case SHISHI_DES_CBC_MD5:
      memset (out + 8, 0, MD5_DIGEST_SIZE);
      md5_init (&md5);
      if (hashzeros)
	md5_update (&md5, 8 + MD5_DIGEST_SIZE, out);
      else
	md5_update (&md5, 8, out);
      md5_update (&md5, inlen, in);

      md5_digest (&md5, MD5_DIGEST_SIZE, out + 8);

      hlen = MD5_DIGEST_SIZE;
      break;
    }

  *outlen = 8 + hlen;
#endif

  return SHISHI_OK;
}

static int
des_encrypt_checksum (Shishi * handle,
		      Shishi_key * key,
		      int keyusage,
		      const char *iv,
		      size_t ivlen,
		      const char *in, size_t inlen, char **out, size_t * outlen,
		      int algo)
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

  res = raw_des_checksum (handle, algo, inpad, inpadlen, cksum, &cksumlen, 1);
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

  res = simplified_encrypt (handle, key, 0, iv, ivlen,
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
		 const char *iv,
		 size_t ivlen,
		 const char *in, size_t inlen, char **out, size_t * outlen)
{
  return des_encrypt_checksum (handle, key, keyusage, iv, ivlen,
			       in, inlen, out, outlen, SHISHI_DES_CBC_CRC);
}

static int
des_md4_encrypt (Shishi * handle,
		 Shishi_key * key,
		 int keyusage,
		 const char *iv,
		 size_t ivlen,
		 const char *in, size_t inlen, char **out, size_t * outlen)
{
  return des_encrypt_checksum (handle, key, keyusage, iv, ivlen,
			       in, inlen, out, outlen, SHISHI_DES_CBC_MD4);
}

static int
des_md5_encrypt (Shishi * handle,
		 Shishi_key * key,
		 int keyusage,
		 const char *iv,
		 size_t ivlen,
		 const char *in, size_t inlen, char **out, size_t * outlen)
{
  return des_encrypt_checksum (handle, key, keyusage, iv, ivlen,
			       in, inlen, out, outlen, SHISHI_DES_CBC_MD5);
}

static int
des_none_encrypt (Shishi * handle,
		  Shishi_key * key,
		  int keyusage,
		  const char *iv,
		  size_t ivlen,
		  const char *in, size_t inlen, char **out, size_t * outlen)
{
  return simplified_encrypt (handle, key, 0, iv, ivlen,
			     in, inlen, out, outlen);
}

static int
des_decrypt_verify (Shishi * handle,
		    Shishi_key * key,
		    int keyusage,
		    const char *iv, size_t ivlen,
		    const char *in, size_t inlen,
		    char **out, size_t * outlen,
		    int algo)
{
  int res;

  res = simplified_decrypt (handle, key, 0, iv, ivlen,
			    in, inlen, out, outlen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "decrypt failed");
      return res;
    }

  res = raw_des_verify (handle, algo, *out, outlen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "verify failed");
      return res;
    }

  return SHISHI_OK;
}

static int
des_crc_decrypt (Shishi * handle,
		 Shishi_key * key,
		 int keyusage,
		 const char *iv,
		 size_t ivlen,
		 const char *in, size_t inlen, char **out, size_t * outlen)
{
  return des_decrypt_verify (handle, key, keyusage, iv, ivlen,
			     in, inlen, out, outlen, SHISHI_DES_CBC_CRC);
}

static int
des_md4_decrypt (Shishi * handle,
		 Shishi_key * key,
		 int keyusage,
		 const char *iv,
		 size_t ivlen,
		 const char *in, size_t inlen, char **out, size_t * outlen)
{
  return des_decrypt_verify (handle, key, keyusage, iv, ivlen,
			     in, inlen, out, outlen, SHISHI_DES_CBC_MD4);
}

static int
des_md5_decrypt (Shishi * handle,
		 Shishi_key * key,
		 int keyusage,
		 const char *iv,
		 size_t ivlen,
		 const char *in, size_t inlen, char **out, size_t * outlen)
{
  return des_decrypt_verify (handle, key, keyusage, iv, ivlen,
			     in, inlen, out, outlen, SHISHI_DES_CBC_MD5);
}

static int
des_none_decrypt (Shishi * handle,
		  Shishi_key * key,
		  int keyusage,
		  const char *iv,
		  size_t ivlen,
		  const char *in, size_t inlen, char **out, size_t * outlen)
{
  return simplified_decrypt (handle, key, 0, iv, ivlen,
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

static int
des_key_correction (Shishi * handle, char *key)
{
#ifdef USE_GCRYPT
  gcry_cipher_hd_t ch;
  gpg_error_t err;

  /* fixparity(key); */
  des_set_odd_key_parity (key);

  err = gcry_cipher_open (&ch, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CBC, 0);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "DES-CBC not available in libgcrypt");
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  /* XXX? libgcrypt tests for pseudo-weak keys, rfc 1510 doesn't */

  err = gcry_cipher_setkey (ch, key, 8);

  gcry_cipher_close (ch);

  if (err != GPG_ERR_NO_ERROR)
    {
      if (gpg_err_code (err) == GPG_ERR_WEAK_KEY)
	{
	  if (VERBOSECRYPTO (handle))
	    printf ("\t ;; WEAK KEY (corrected)\n");
	  key[7] ^= 0xF0;
	}
      else
	{
	  shishi_error_printf (handle, "DES setkey failed");
	  shishi_error_set (handle, gpg_strerror (err));
	  return SHISHI_CRYPTO_INTERNAL_ERROR;
	}
    }
#else
  struct CBC_MAC_CTX (struct des_ctx, DES_BLOCK_SIZE) des;
  int rc;

  /* fixparity(key); */
  des_set_odd_key_parity (key);

  rc = des_set_key (&des.ctx, key);
  if (!rc && des.ctx.status == DES_WEAK_KEY)
    {
      if (VERBOSECRYPTO (handle))
	printf ("\t ;; WEAK KEY (corrected)\n");
      key[7] ^= 0xF0;
    }
#endif

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
des_cbc_check (Shishi * handle, char key[8], char *data, int n_data)
{
#ifdef USE_GCRYPT
  gcry_cipher_hd_t ch;
  gpg_error_t err;
  int res = SHISHI_CRYPTO_INTERNAL_ERROR;

  err = gcry_cipher_open (&ch, GCRY_CIPHER_DES,
			  GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_MAC);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "DES-CBC-MAC not available in libgcrypt");
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  err = gcry_cipher_setkey (ch, key, 8);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "DES setkey failed");
      shishi_error_set (handle, gpg_strerror (err));
      goto done;
    }

  err = gcry_cipher_setiv (ch, key, 8);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "DES setiv failed");
      shishi_error_set (handle, gpg_strerror (err));
      goto done;
    }

  err = gcry_cipher_encrypt (ch, key, 8, data, n_data);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "DES encrypt failed");
      shishi_error_set (handle, gpg_strerror (err));
      goto done;
    }

  return SHISHI_OK;

 done:
  gcry_cipher_close (ch);
  return res;
#else
  struct CBC_MAC_CTX (struct des_ctx, DES_BLOCK_SIZE) des;
  int rc;

  rc = des_set_key (&des.ctx, key);
  if (!rc)
    {
      shishi_error_printf (handle, "des_set_key() failed (%d)", rc);
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  CBC_SET_IV (&des, key);

  CBC_ENCRYPT (&des, des_encrypt, n_data, key, data);

  return SHISHI_OK;
#endif
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

  if (saltlen < 0)
    saltlen = 0;

  odd = 1;
  n_s = stringlen + saltlen;
  if ((n_s % 8) != 0)
    n_s += 8 - n_s % 8;
  s = (char *) malloc (n_s);
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

  res = des_cbc_check (handle, tempkey, s, n_s);
  if (res != SHISHI_OK)
    return res;

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
	      char *in, size_t inlen, char **out, size_t * outlen,
	      int algo)
{
  char buffer[BUFSIZ];
  int buflen;
  char *keyp;
  int i;
  int res;

  buflen = sizeof (buffer);
  res = raw_des_checksum (handle, algo, in, inlen, buffer, &buflen, 0);
  if (res != SHISHI_OK)
    {
      shishi_error_set (handle, "checksum failed");
      return res;
    }

  keyp = shishi_key_value (key);

  for (i = 0; i < 8; i++)
    keyp[i] ^= 0xF0;

  res = simplified_dencrypt (handle, key, NULL, 0, buffer, buflen,
			     out, outlen, 0);

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
		  char *in, size_t inlen, char **out, size_t * outlen)
{
  return des_checksum (handle, key, keyusage, cksumtype,
		       in, inlen, out, outlen,
		       SHISHI_RSA_MD4_DES);
}

static int
des_md5_checksum (Shishi * handle,
		  Shishi_key * key,
		  int keyusage,
		  int cksumtype,
		  char *in, size_t inlen, char **out, size_t * outlen)
{
  return des_checksum (handle, key, keyusage, cksumtype,
		       in, inlen, out, outlen,
		       SHISHI_RSA_MD5_DES);
}
