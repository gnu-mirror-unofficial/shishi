/* crypto-3des.c	3DES related RFC 1510 crypto functions
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

static int
des3_cbc_sha1_kd_checksum (Shishi * handle,
			   char *out,
			   int *outlen, char *in, int inlen)
{
  int res;
  char buffer[BUFSIZ];
  char confounder[8];
  char md[16];
  GCRY_MD_HD hd;
  int i;

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

#if 0
  printf ("cksum random: ");
  for (i = 0; i < 8; i++)
    printf ("%02X ", buffer[i]);
  printf ("\n");
#endif

  hd = gcry_md_open (GCRY_MD_MD5, 0);
  if (hd)
    {
      char *p;

      gcry_md_write (hd, buffer, inlen + 8 + 16);
      p = gcry_md_read (hd, GCRY_MD_MD5);

#if 0
      printf ("cksum md5: ");
      for (i = 0; i < 16; i++)
	printf ("%02X ", p[i]);
      printf ("\n");
#endif

      memcpy (buffer + 8, p, 16);
      gcry_md_close (hd);
    }
  else
    {
      puts ("bajs");
      exit (1);
    }

  memcpy (out, buffer, 8 + 16);

  *outlen = 8 + 16;

  return SHISHI_OK;
}

static int
des3_cbc_sha1_kd_verify (Shishi * handle, char *out, int *outlen,
			 char *key)
{
  GCRY_MD_HD mdh;
  char *hash;
  int i;
  int res;

  res = gcry_control (GCRYCTL_INIT_SECMEM, 512, 0);
  if (res != GCRYERR_SUCCESS)
    return SHISHI_GCRYPT_ERROR;

  mdh = gcry_md_open (GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
  if (mdh == NULL)
    return SHISHI_GCRYPT_ERROR;

  res = gcry_md_setkey (mdh, key, 24);
  if (res != GCRYERR_SUCCESS)
    return SHISHI_GCRYPT_ERROR;

  gcry_md_write (mdh, out, *outlen-24);
  
  hash = gcry_md_read (mdh, GCRY_MD_SHA1);
  if (hash == NULL)
    return SHISHI_GCRYPT_ERROR;

#if 0
  printf("hash: ");
  for (i = 0; i < 21; i++)
    printf("%02x", hash[i]);
  printf("\n");
#endif

  memmove (out, out + 8, *outlen - 8);
  *outlen -= 8 + 24;
  return SHISHI_OK;
}

/* The 168 bits of random key data are converted to a protocol key
 * value as follows.  First, the 168 bits are divided into three
 * groups of 56 bits, which are expanded individually into 64 bits as
 * follows:
 *
 *          1  2  3  4  5  6  7  p
 *          9 10 11 12 13 14 15  p
 *         17 18 19 20 21 22 23  p
 *         25 26 27 28 29 30 31  p
 *         33 34 35 36 37 38 39  p
 *         41 42 43 44 45 46 47  p
 *         49 50 51 52 53 54 55  p
 *         56 48 40 32 24 16  8  p
 *
 * The "p" bits are parity bits computed over the data bits.  The
 * output of the three expansions are concatenated to form the
 * protocol key value.
 *
 */
static int
des3_random_to_key (Shishi * handle,
		    int keytype,
		    char random[168 / 8], 
		    int randomlen,
		    char key[3 * 8])
{
  int i;

  if (DEBUGCRYPTO(handle))
    {
      printf ("des3_random_to_key (random)\n");
      printf ("\t ;; random (length %d):\n", 168 / 8);
      hexprint (random, 168 / 8);
      puts ("");
      binprint (random, 168 / 8);
      puts ("");
    }

  memcpy (key, random, 7);
  memcpy (key + 8, random + 7, 7);
  memcpy (key + 16, random + 14, 7);
  for (i = 0; i < 3; i++)
    {
      key[i * 8 + 7] =
	((key[i * 8 + 0] & 0x01) << 1) |
	((key[i * 8 + 1] & 0x01) << 2) |
	((key[i * 8 + 2] & 0x01) << 3) |
	((key[i * 8 + 3] & 0x01) << 4) |
	((key[i * 8 + 4] & 0x01) << 5) |
	((key[i * 8 + 5] & 0x01) << 6) | ((key[i * 8 + 6] & 0x01) << 7);
      des_set_odd_key_parity (key + i * 8);
    }

  if (DEBUGCRYPTO(handle))
    {
      printf ("key = des3_random_to_key (random)\n");
      printf ("\t ;; key:\n");
      hexprint (key, 3 * 8);
      puts ("");
      binprint (key, 3 * 8);
      puts ("");
    }

  return SHISHI_OK;
}

static int
des3_string_to_key (Shishi * handle,
		    int keytype,
		    char *string,
		    int stringlen,
		    char *salt,
		    int saltlen,
		    char *parameter,
		    char *outkey)
{
  char *s;
  int n_s;
  int odd;
  char key[3 * 8];
  char nfold[168 / 8];
  int i, j;
  char temp, temp2;
  int res;
  int keylen = shishi_cipher_keylen (keytype);

  if (DEBUGCRYPTO(handle))
    {
      printf ("des3_string_to_key (string, salt)\n");

      printf ("\t ;; String:\n");
      escapeprint (string, stringlen);
      hexprint (string, stringlen);
      puts ("");
      puts ("");

      printf ("\t ;; Salt:\n");
      escapeprint (salt, saltlen);
      hexprint (salt, saltlen);
      puts ("");
    }

  /* s = passwordString + salt */
  n_s = stringlen + saltlen;
  s = (char *) malloc (n_s);
  memcpy (s, string, stringlen);
  memcpy (s + stringlen, salt, saltlen);

  res = shishi_n_fold (handle, s, n_s, nfold, 168 / 8);
  if (res != SHISHI_OK)
    return res;

  res = des3_random_to_key (handle, keytype, nfold, 168 / 8, key);
  if (res != SHISHI_OK)
    return res;

  res = shishi_dk (handle, SHISHI_DES3_CBC_HMAC_SHA1_KD,
		   key, 3 * 8,
		   "kerberos", strlen ("kerberos"), outkey, 3 * 8);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}
