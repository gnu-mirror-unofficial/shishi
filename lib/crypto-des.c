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
des_crc_verify (Shishi * handle, char *out, int *outlen)
{
  int res;
  char md[16];
  GCRY_MD_HD hd;
  char *p;

  memcpy (md, out + 8, 4);
  memset (out + 8, 0, 4);

  hd = gcry_md_open (GCRY_MD_CRC32_RFC1510, 0);

  if (!hd)
    {
      puts("CRC not available");
      return !SHISHI_OK;
    }

  gcry_md_write (hd, out, *outlen);
  p = gcry_md_read (hd, GCRY_MD_CRC32_RFC1510);
  if (VERBOSECRYPTO(handle))
    {
      int i;

      for (i = 0; i < 4; i++)
	printf ("%02X ", md[i] & 0xFF);
      printf ("\n");
      for (i = 0; i < 4; i++)
	printf ("%02X ", p[i] & 0xFF);
      printf ("\n");
    }

  if (memcmp (p, md, 4) == 0)
    {
      memmove (out, out + 8 + 4, *outlen - 8 - 4);
      *outlen -= 8 + 4;
      res = SHISHI_OK;
    }
  else
    {
      if (VERBOSE(handle))
	printf ("des-cbc-crc verify fail\n");
      res = !SHISHI_OK;
    }

  gcry_md_close (hd);

  return res;
}

static int
des_crc_checksum (Shishi * handle,
		  char *out, size_t *outlen,
		  const char *in, size_t inlen)
{
  int res;
  char buffer[BUFSIZ];
  char *p;
  GCRY_MD_HD hd;

  if (inlen + 8 + 4 > BUFSIZ)
    {
      shishi_error_printf (handle, "checksum inbuffer too large");
      return !SHISHI_OK;
    }

  memcpy (buffer + 8 + 4, in, inlen);
  memset (buffer + 8, 0, 4);

  res = shishi_randomize (handle, buffer, 8);
  if (res != SHISHI_OK)
    return res;

  hd = gcry_md_open (GCRY_MD_CRC32_RFC1510, 0);
  if (hd == NULL)
    return SHISHI_GCRYPT_ERROR;

  gcry_md_write (hd, buffer, inlen + 8 + 4);
  p = gcry_md_read (hd, GCRY_MD_CRC32_RFC1510);

  memcpy (buffer + 8, p, 4);
  gcry_md_close (hd);

  memcpy (out, buffer, 8 + 4);

  *outlen = 8 + 4;

  return SHISHI_OK;
}

static int
des_md4_verify (Shishi * handle, char *out, int *outlen)
{
  int res;
  char md[16];
  GCRY_MD_HD hd;
  char *p;

  memcpy (md, out + 8, 16);
  memset (out + 8, 0, 16);

  hd = gcry_md_open (GCRY_MD_MD4, 0);

  if (!hd)
    {
      puts("MD4 not available");
      return !SHISHI_OK;
    }

  gcry_md_write (hd, out, *outlen);
  p = gcry_md_read (hd, GCRY_MD_MD4);
  if (VERBOSECRYPTO(handle))
    {
      int i;

      for (i = 0; i < 16; i++)
	printf ("%02X ", md[i] & 0xFF);
      printf ("\n");
      for (i = 0; i < 16; i++)
	printf ("%02X ", p[i] & 0xFF);
      printf ("\n");
    }

  if (memcmp (p, md, 16) == 0)
    {
      memmove (out, out + 8 + 16, *outlen - 8 - 16);
      *outlen -= 8 + 16;
      res = SHISHI_OK;
    }
  else
    {
      if (VERBOSE(handle))
	printf ("des-cbc-md4 verify fail\n");
      res = !SHISHI_OK;
    }

  gcry_md_close (hd);

  return res;
}

static int
des_md4_checksum (Shishi * handle,
		  char *out, size_t *outlen,
		  const char *in, size_t inlen)
{
  int res;
  char buffer[BUFSIZ];
  char *p;
  GCRY_MD_HD hd;

  if (inlen + 8 + 16 > BUFSIZ)
    {
      shishi_error_printf (handle, "checksum inbuffer too large");
      return !SHISHI_OK;
    }

  memcpy (buffer + 8 + 16, in, inlen);
  memset (buffer + 8, 0, 16);

  res = shishi_randomize (handle, buffer, 8);
  if (res != SHISHI_OK)
    return res;

  hd = gcry_md_open (GCRY_MD_MD4, 0);
  if (hd == NULL)
    return SHISHI_GCRYPT_ERROR;

  gcry_md_write (hd, buffer, inlen + 8 + 16);
  p = gcry_md_read (hd, GCRY_MD_MD4);

  memcpy (buffer + 8, p, 16);
  gcry_md_close (hd);

  memcpy (out, buffer, 8 + 16);

  *outlen = 8 + 16;

  return SHISHI_OK;
}

static int
des_md5_verify (Shishi * handle, char *out, int *outlen)
{
  int res;
  char md[16];
  GCRY_MD_HD hd;
  char *p;

  memcpy (md, out + 8, 16);
  memset (out + 8, 0, 16);

  hd = gcry_md_open (GCRY_MD_MD5, 0);

  if (!hd)
    {
      shishi_error_set (handle, "MD5 not available");
      return !SHISHI_OK;
    }

  gcry_md_write (hd, out, *outlen);
  p = gcry_md_read (hd, GCRY_MD_MD5);
  if (VERBOSECRYPTO(handle))
    {
      int i;

      for (i = 0; i < 16; i++)
	printf ("%02X ", md[i] & 0xFF);
      printf ("\n");
      for (i = 0; i < 16; i++)
	printf ("%02X ", p[i] & 0xFF);
      printf ("\n");
    }

  if (memcmp (p, md, 16) == 0)
    {
      memmove (out, out + 8 + 16, *outlen - 8 - 16);
      *outlen -= 8 + 16;
      res = SHISHI_OK;
    }
  else
    {
      if (VERBOSE(handle))
	printf ("des-cbc-md5 verify fail\n");
      res = !SHISHI_OK;
    }

  gcry_md_close (hd);

  return res;
}

static int
des_md5_checksum (Shishi * handle,
		  char *out, size_t *outlen,
		  const char *in, size_t inlen)
{
  int res;
  char buffer[BUFSIZ];
  char *p;
  GCRY_MD_HD hd;

  if (inlen + 8 + 16 > BUFSIZ)
    {
      shishi_error_printf (handle, "checksum inbuffer too large");
      return !SHISHI_OK;
    }

  memcpy (buffer + 8 + 16, in, inlen);
  memset (buffer + 8, 0, 16);

  res = shishi_randomize (handle, buffer, 8);
  if (res != SHISHI_OK)
    return res;

  hd = gcry_md_open (GCRY_MD_MD5, 0);
  if (hd == NULL)
    return SHISHI_GCRYPT_ERROR;

  gcry_md_write (hd, buffer, inlen + 8 + 16);
  p = gcry_md_read (hd, GCRY_MD_MD5);

  memcpy (buffer + 8, p, 16);
  gcry_md_close (hd);

  memcpy (out, buffer, 8 + 16);

  *outlen = 8 + 16;

  return SHISHI_OK;
}

static int
des_crc_encrypt (Shishi * handle,
		 Shishi_key *key,
		 int keyusage,
		 const char *iv,
		 size_t ivlen,
		 const char *in,
		 size_t inlen,
		 char *out,
		 size_t *outlen)
{
  char buffer[BUFSIZ];
  char buffer2[BUFSIZ];
  int buflen;
  int buf2len;
  int res;

  memcpy(buffer2, in, inlen);
  buf2len = inlen;

  while ((buf2len % 8) != 0)
    {
      buffer2[buf2len] = '\0'; /* XXX */
      buf2len++;
    }

  buflen = sizeof (buffer);
  res = des_crc_checksum (handle, buffer, &buflen, buffer2, buf2len);
  memcpy (buffer + buflen, buffer2, buf2len);
  buflen += buf2len;
  res = simplified_encrypt (handle, key, 0, iv, ivlen,
			    buffer, buflen, out, outlen);

  return res;
}

static int
des_crc_decrypt (Shishi * handle,
		 Shishi_key *key,
		 int keyusage,
		 const char *iv,
		 size_t ivlen,
		 const char *in,
		 size_t inlen,
		 char *out,
		 size_t *outlen)
{
  int res;

  printf("in %d\n", inlen);
  res = simplified_decrypt (handle, key, 0, iv, ivlen,
			    in, inlen, out, outlen);
  if (res != SHISHI_OK)
    {
      shishi_error_set (handle, "decrypt failed");
      return res;
    }
#if 0
  memcpy(out, "\x56\xcc\xa9\xd6\x67\x0a\xca\x0e\xbc\x58\xdc\x9b\x79\x81\xd3\x30\x81\xd0\xa0\x13\x30\x11\xa0\x03\x02\x01\x01\xa1\x0a\x04\x08\x8f\x75\x58\x45\x9d\x31\x6b\x1f\xa1\x1c\x30\x1a\x30\x18\xa0\x03\x02\x01\x00\xa1\x11\x18\x0f\x31\x39\x37\x30\x30\x31\x30\x31\x30\x30\x30\x30\x30\x30\x5a\xa2\x06\x02\x04\x3d\xdd\x3a\x46\xa4\x07\x03\x05\x00\x50\x40\x00\x00\xa5\x11\x18\x0f\x32\x30\x30\x32\x31\x31\x32\x31\x31\x39\x35\x35\x35\x30\x5a\xa7\x11\x18\x0f\x32\x30\x30\x32\x31\x31\x32\x32\x30\x35\x35\x35\x35\x30\x5a\xa9\x0f\x1b\x0d\x4a\x4f\x53\x45\x46\x53\x53\x4f\x4e\x2e\x4f\x52\x47\xaa\x22\x30\x20\xa0\x03\x02\x01\x00\xa1\x19\x30\x17\x1b\x06\x6b\x72\x62\x74\x67\x74\x1b\x0d\x4a\x4f\x53\x45\x46\x53\x53\x4f\x4e\x2e\x4f\x52\x47\xab\x2f\x30\x2d\x30\x0d\xa0\x03\x02\x01\x02\xa1\x06\x04\x04\xc0\xa8\x01\x01\x30\x0d\xa0\x03\x02\x01\x02\xa1\x06\x04\x04\xc0\xa8\x02\x01\x30\x0d\xa0\x03\x02\x01\x02\xa1\x06\x04\x04\xd9\xd0\xac\x49\x00\x00\x00\x00\x00\x00", 232);
   *outlen = 232;
#endif
    {
      size_t i;
      printf("decrypt %d\n", *outlen);
      for(i=0; i < *outlen; i++)
	printf("%02x ", ((char*)out)[i] & 0xFF);
      printf("\n");
    }
  res = des_crc_verify (handle, out, outlen);
  if (res != SHISHI_OK)
    {
      shishi_error_set (handle, "verify failed");
      return res;
    }

  return res;
}

static int
des_md4_encrypt (Shishi * handle,
		 Shishi_key *key,
		 int keyusage,
		 const char *iv,
		 size_t ivlen,
		 const char *in,
		 size_t inlen,
		 char *out,
		 size_t *outlen)
{
  char buffer[BUFSIZ];
  char buffer2[BUFSIZ];
  size_t buflen;
  size_t buf2len;
  int res;

  memcpy(buffer2, in, inlen);
  buf2len = inlen;
  while ((buf2len % 8) != 0)
    {
      buffer2[buf2len] = '\0'; /* XXX */
      buf2len++;
    }

  buflen = sizeof (buffer);
  res = des_md4_checksum (handle, buffer, &buflen, buffer2, buf2len);
  memcpy (buffer + buflen, buffer, buf2len);
  buflen += buf2len;
  res = simplified_encrypt (handle, key, 0, iv, ivlen,
			    buffer, buflen, out, outlen);

  return res;
}

static int
des_md4_decrypt (Shishi * handle,
		 Shishi_key *key,
		 int keyusage,
		 const char *iv,
		 size_t ivlen,
		 const char *in,
		 size_t inlen,
		 char *out,
		 size_t *outlen)
{
  int res;

  res = simplified_decrypt (handle, key, 0, iv, ivlen,
			    in, inlen, out, outlen);
  if (res != SHISHI_OK)
    {
      shishi_error_set (handle, "decrypt failed");
      return res;
    }
  res = des_md4_verify (handle, out, outlen);
  if (res != SHISHI_OK)
    {
      shishi_error_set (handle, "verify failed");
      return res;
    }

  return res;
}

static int
des_md5_encrypt (Shishi * handle,
		 Shishi_key *key,
		 int keyusage,
		 const char *iv,
		 size_t ivlen,
		 const char *in,
		 size_t inlen,
		 char *out,
		 size_t *outlen)
{
  char buffer[BUFSIZ];
  char buffer2[BUFSIZ];
  size_t buflen;
  size_t buf2len;
  int res;

  memcpy(buffer2, in, inlen);
  buf2len = inlen;

  while ((buf2len % 8) != 0)
    {
      buffer2[buf2len] = '\0'; /* XXX */
      buf2len++;
    }

  buflen = sizeof (buffer);
  res = des_md5_checksum (handle, buffer, &buflen, buffer2, buf2len);
  memcpy (buffer + buflen, buffer2, buf2len);
  buflen += buf2len;
  res = simplified_encrypt (handle, key, 0, iv, ivlen,
			    buffer, buflen, out, outlen);

  return res;
}

static int
des_md5_decrypt (Shishi * handle,
		 Shishi_key *key,
		 int keyusage,
		 const char *iv,
		 size_t ivlen,
		 const char *in,
		 size_t inlen,
		 char *out,
		 size_t *outlen)
{
  int res;

  res = simplified_decrypt (handle, key, 0, iv, ivlen,
			    in, inlen, out, outlen);
  if (res != SHISHI_OK)
    {
      shishi_error_set (handle, "decrypt failed");
      return res;
    }
  res = des_md5_verify (handle, out, outlen);
  if (res != SHISHI_OK)
    {
      shishi_error_set (handle, "verify failed");
      return res;
    }

  return res;
}

static int
des_none_encrypt (Shishi * handle,
		  Shishi_key *key,
		  int keyusage,
		  const char *iv,
		  size_t ivlen,
		  const char *in,
		  size_t inlen,
		  char *out,
		  size_t *outlen)
{
  int res;

  res = simplified_encrypt (handle, key, 0, iv, ivlen,
			    in, inlen, out, outlen);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

static int
des_none_decrypt (Shishi * handle,
		  Shishi_key *key,
		  int keyusage,
		  const char *iv,
		  size_t ivlen,
		  const char *in,
		  size_t inlen,
		  char *out,
		  size_t *outlen)
{
  int res;

  res = simplified_decrypt (handle, key, 0, iv, ivlen,
			    in, inlen, out, outlen);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
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
  int res;
  GCRY_CIPHER_HD ch;

  /* fixparity(key); */
  des_set_odd_key_parity (key);

  ch = gcry_cipher_open (GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CBC, 0);
  if (ch == NULL)
    return !SHISHI_OK;

  /* XXX libgcrypt tests for pseudo-weak keys, rfc 1510 doesn't */

  res = gcry_cipher_setkey (ch, key, 8);
  if (res != GCRYERR_SUCCESS)
    {
      if (res == GCRYERR_WEAK_KEY)
	{
	  if (VERBOSECRYPTO(handle))
	    printf ("\t ;; WEAK KEY (corrected)\n");
	  key[7] ^= 0xF0;
	}
      else
	return !SHISHI_OK;
    }

  gcry_cipher_close (ch);

  return SHISHI_OK;
}

static int
des_cbc_check (char key[8], char *data, int n_data)
{
  GCRY_CIPHER_HD ch;
  int res;

  ch = gcry_cipher_open (GCRY_CIPHER_DES,
			 GCRY_CIPHER_MODE_CBC,
			 GCRY_CIPHER_CBC_MAC);
  if (ch == NULL)
    return SHISHI_GCRYPT_ERROR;

  res = gcry_cipher_setkey (ch, key, 8);
  if (res != GCRYERR_SUCCESS)
    return SHISHI_GCRYPT_ERROR;

  res = gcry_cipher_setiv (ch, key, 8);
  if (res != 0)
    return SHISHI_GCRYPT_ERROR;

  res = gcry_cipher_encrypt (ch, key, 8, data, n_data);
  if (res != 0)
    return SHISHI_GCRYPT_ERROR;

  gcry_cipher_close (ch);

  return SHISHI_OK;
}

static int
des_random_to_key (Shishi * handle,
		   const char *random,
		   size_t randomlen,
		   Shishi_key *outkey)
{
  char tmp[MAX_RANDOM_LEN];
  int keylen = shishi_cipher_keylen (shishi_key_type(outkey));

  if (randomlen != shishi_key_length(outkey))
    return !SHISHI_OK;

  memcpy(tmp, random, keylen);
  des_set_odd_key_parity (tmp);

  shishi_key_value_set(outkey, tmp);

  return SHISHI_OK;
}

static int
des_string_to_key (Shishi * handle,
		   const char *string,
		   size_t stringlen,
		   const char *salt,
		   size_t saltlen,
		   const char *parameter,
		   Shishi_key *outkey)
{
  char *s;
  int n_s;
  int odd;
  char tempkey[8];
  int i, j;
  char temp, temp2;
  int res;

  if (VERBOSECRYPTO(handle))
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

  if (VERBOSECRYPTO(handle))
    {
      printf ("\t ;; s = pad(string|salt):\n");
      escapeprint (s, n_s);
      hexprint (s, n_s);
      puts ("");
    }

  for (i = 0; i < n_s / 8; i++)
    {
      if (VERBOSECRYPTO(handle))
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

      if (VERBOSECRYPTO(handle))
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
	  if (VERBOSECRYPTO(handle))
	    {
	      printf ("reverse(56bitstring)\n");
	      printf ("\t ;; 56bitstring after reverse\n");
	      bin7print (&s[i * 8], 8);
	      puts ("");
	    }
	}

      odd = !odd;

      if (VERBOSECRYPTO(handle))
	{
	  printf ("odd = ! odd\n");
	  printf ("tempstring = tempstring XOR 56bitstring;\n");
	}

      /* tempkey = tempkey XOR 8byteblock; */
      for (j = 0; j < 8; j++)
	tempkey[j] ^= s[i * 8 + j];

      if (VERBOSECRYPTO(handle))
	{
	  printf ("\t ;; tempstring\n");
	  bin7print (tempkey, 8);
	  puts ("");
	  puts ("");
	}
    }

  for (j = 0; j < 8; j++)
    tempkey[j] = tempkey[j] << 1;

  if (VERBOSECRYPTO(handle))
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

  if (VERBOSECRYPTO(handle))
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

  res = des_cbc_check (tempkey, s, n_s);
  if (res != SHISHI_OK)
    return res;

  res = des_key_correction (handle, tempkey);
  if (res != SHISHI_OK)
    return res;

  if (VERBOSECRYPTO(handle))
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
checksum_md4 (Shishi * handle,
	      char *out, int *outlen, char *in, int inlen)
{
  int res;
  char buffer[BUFSIZ];
  GCRY_MD_HD hd;
  char *p;

  if (inlen + 8 > BUFSIZ)
    {
      shishi_error_printf (handle, "checksum inbuffer too large");
      return !SHISHI_OK;
    }

  memcpy (buffer + 8, in, inlen);

#if 0
  printf ("cksum in len=%d:", inlen);
  for (i = 0; i < inlen; i++)
    printf ("%02x ", in[i] & 0xFF);
  printf ("\n");
#endif

  res = shishi_randomize (handle, buffer, 8);
  if (res != SHISHI_OK)
    return res;

#if 0
  printf ("cksum random: ");
  for (i = 0; i < 8; i++)
    printf ("%02X ", buffer[i] & 0xFF);
  printf ("\n");
#endif

  hd = gcry_md_open (GCRY_MD_MD4, 0);
  if (!hd)
    return SHISHI_GCRYPT_ERROR;

  gcry_md_write (hd, buffer, inlen + 8);
  p = gcry_md_read (hd, GCRY_MD_MD4);

#if 0
  printf ("cksum md4: ");
  for (i = 0; i < 16; i++)
    printf ("%02X ", p[i] & 0xFF);
  printf ("\n");
#endif

  memcpy (buffer + 8, p, 16);
  gcry_md_close (hd);

  memcpy (out, buffer, 8 + 16);

  *outlen = 8 + 16;

#if 0
  printf ("cksum out: ");
  for (i = 0; i < *outlen; i++)
    printf ("%02X ", out[i] & 0xFF);
  printf ("\n");
#endif

  return SHISHI_OK;
}

static int
checksum_md5 (Shishi * handle,
	      char *out, int *outlen, char *in, int inlen)
{
  int res;
  char buffer[BUFSIZ];
  GCRY_MD_HD hd;
  char *p;

  if (inlen + 8 > BUFSIZ)
    {
      shishi_error_printf (handle, "checksum inbuffer too large");
      return !SHISHI_OK;
    }

  memcpy (buffer + 8, in, inlen);

#if 0
  printf ("cksum in len=%d:", inlen);
  for (i = 0; i < inlen; i++)
    printf ("%02x ", in[i] & 0xFF);
  printf ("\n");
#endif

  res = shishi_randomize (handle, buffer, 8);
  if (res != SHISHI_OK)
    return res;

#if 0
  printf ("cksum random: ");
  for (i = 0; i < 8; i++)
    printf ("%02X ", buffer[i] & 0xFF);
  printf ("\n");
#endif

  hd = gcry_md_open (GCRY_MD_MD5, 0);
  if (!hd)
    return SHISHI_GCRYPT_ERROR;

  gcry_md_write (hd, buffer, inlen + 8);
  p = gcry_md_read (hd, GCRY_MD_MD5);

#if 0
  printf ("cksum md5: ");
  for (i = 0; i < 16; i++)
    printf ("%02X ", p[i] & 0xFF);
  printf ("\n");
#endif

  memcpy (buffer + 8, p, 16);
  gcry_md_close (hd);

  memcpy (out, buffer, 8 + 16);

  *outlen = 8 + 16;

#if 0
  printf ("cksum out: ");
  for (i = 0; i < *outlen; i++)
    printf ("%02X ", out[i] & 0xFF);
  printf ("\n");
#endif

  return SHISHI_OK;
}
