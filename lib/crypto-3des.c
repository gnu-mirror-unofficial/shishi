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

#if 0
	  printf ("pos %3d mask %3d (%02x): %3d/%02x "
		  "pos %3d mask %3d (%02x): %3d/%02x\n",
		  pos, mask, ~mask & 0xFF, (out[pos] & mask), 
		  (out[pos] & mask),
		  pos2, mask2, mask2, (in[pos2] & mask2), (in[pos2] & mask2));
#endif

	  out[pos] = 
	    (out[pos] & mask) | (((in[pos2] & mask2) ? 0xFF : 0x00) & ~mask);
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

/*

From http://www.cs.wisc.edu/~cs354-1/karen.notes/arith.int.html:

one's complement:
  
by example


00111 (7)         111110 (-1)            11110 (-1)
+ 00101 (5)       + 000010 (2)           + 11100 (-3)
-----------       ------------           ------------
01100 (12)      1 000000 (0) wrong!    1 11010 (-5) wrong!
+  1                  +  1
----------             ----------
000001 (1) right!      11011 (-4) right!


So, it seems that if there is a carry out of the msb, then
the result will be off by 1, so add 1 again to get the correct
result.  (Implementation in HW called an "end around carry.")
*/

static int
ocadd (unsigned char *add1, unsigned char *add2, unsigned char *sum, int len)
{
  int i;
  int carry = 0;

  for (i = len - 1; i >= 0; i--)
    {
      unsigned int tmpsum = add1[i] + add2[i];

#if 0
      printf ("iter %d value %02x (carry) + %02x+%02x=%03x ", i,
	      carry, add1[i], add2[i], add1[i] + add2[i]);
#endif

      sum[i] = 0xFF & (tmpsum + carry);
      if ((tmpsum + carry) & ~0xFF)
	carry = 1;
      else
	carry = 0;
#if 0
      if (carry)
	printf ("overflow stored\n");
      else
	printf ("no overflow\n");
#endif
    }
  if (carry)
    {
      int done = 0;
#if 0
      puts ("final carry");
#endif
      for (i = len - 1; i >= 0; i--)
	{
#if 0
	  printf ("iter %d value %02x: ", i, sum[i]);
#endif
	  if (sum[i] != 0xFF)
	    {
	      sum[i]++;
#if 0
	      printf ("now %02x\n", sum[i]);
#endif
	      done = 1;
	      break;
	    }
	  else
	    {
#if 0
	      printf ("skipping...\n");
#endif
	    }
	}
      if (!done)
	{
#if 0
	  printf ("complete overflow\n");
#endif
	  memset (sum, 0, len);
	}
    }

  return SHISHI_OK;
}

static int
des3_encrypt (Shishi * handle,
	      char *out,
	      int *outlen,
	      char *in, int inlen, char key[3 * 8])
{
  return gcrypt (handle, GCRY_CIPHER_3DES, out, outlen, in, inlen, key, 3 * 8,
		 0);
}

static int
des3_decrypt (Shishi * handle,
	      char *out,
	      int *outlen,
	      char *in, int inlen, char key[3 * 8])
{
  return gcrypt (handle, GCRY_CIPHER_3DES, out, outlen, in, inlen, key, 3 * 8,
		 1);
}

#define DES3_DERIVEKEY_CONSTANTLEN 5

static int
des3_derivekey (Shishi *handle,
		int derivekeymode,
		int keyusage,
		char *key,
		int keylen,
		char *derivedkey,
		int *derivedkeylen)
{
  char constant[DES3_DERIVEKEY_CONSTANTLEN];
  int res;

  if (DEBUGCRYPTO(handle))
    {
      printf ("des3_derivekey\n");
      printf ("\t ;; mode %d (%s)\n", derivekeymode,
	      derivekeymode == SHISHI_DERIVEKEYMODE_CHECKSUM ? "checksum" :
	      derivekeymode == SHISHI_DERIVEKEYMODE_INTEGRITY ? "integrity" :
	      "privacy");
      hexprint (key, keylen);
      puts ("");
    }

  if (*derivedkeylen < keylen)
    return SHISHI_DERIVEDKEY_TOO_SMALL;

  *derivedkeylen = keylen;
  
  keyusage = htonl(keyusage);
  memcpy(constant, &keyusage, DES3_DERIVEKEY_CONSTANTLEN-1);
  if (derivekeymode == SHISHI_DERIVEKEYMODE_CHECKSUM)
    memcpy(&constant[DES3_DERIVEKEY_CONSTANTLEN-1], "\x99", 1);
  else if (derivekeymode == SHISHI_DERIVEKEYMODE_INTEGRITY)
    memcpy(&constant[DES3_DERIVEKEY_CONSTANTLEN-1], "\x55", 1);
  else /* if (derivekeymode == SHISHI_DERIVEKEYMODE_PRIVACY) */
    memcpy(&constant[DES3_DERIVEKEY_CONSTANTLEN-1], "\xAA", 1);

  res = shishi_dk (handle, SHISHI_DES3_CBC_HMAC_SHA1_KD, key, keylen, 
		   constant, DES3_DERIVEKEY_CONSTANTLEN,
		   derivedkey, *derivedkeylen);

  if (DEBUGCRYPTO(handle))
    {
      printf ("\t ;; des3_derivekey out:\n");
      hexprint (derivedkey, *derivedkeylen);
      puts ("");
    }

  return res;
}

static int
des3_cbc_sha1_kd_checksum (Shishi * handle,
			   char *out,
			   int *outlen, char *in, int inlen)
{
#if 0
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
#endif
  *outlen = 0;
  return SHISHI_OK;
}

static int
des3_cbc_sha1_kd_encrypt (Shishi * handle,
			  char *out,
			  int *outlen,
			  char *in, int inlen, char *key)
{
  char buffer[BUFSIZ];
  int buflen;
  int res;

  buflen = sizeof (buffer);
  res = des3_cbc_sha1_kd_checksum (handle, buffer, &buflen, in, inlen);
  memcpy (buffer + buflen, in, inlen);
  buflen += inlen;
  res = des3_encrypt (handle, out, outlen, buffer, buflen, key);

  return res;
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

static int
des3_cbc_sha1_kd_decrypt (Shishi * handle,
			  char *out,
			  int *outlen,
			  char *in, int inlen, char *key)
{
  int res;
  char derivedkey[50];
  int derivedkeylen = 24;

  derivedkeylen = MAX_DERIVEDKEY_LEN;
  res = des3_derivekey(handle, SHISHI_DERIVEKEYMODE_PRIVACY, 
		       SHISHI_KEYUSAGE_ENCASREPPART, key, 24,
		       derivedkey, &derivedkeylen);
  if (res != SHISHI_OK)
    return res;

  res = des3_decrypt (handle, out, outlen, in, inlen, derivedkey);
  if (res != SHISHI_OK)
    {
      shishi_error_set (handle, "decrypt failed");
      return res;
    }

  {
    FILE *fh;
    fh = fopen("hhh", "w");
    if (fh)
      {
	fwrite (out, sizeof (out[0]), *outlen, fh);
	fclose(fh);
      }
  }

  derivedkeylen = MAX_DERIVEDKEY_LEN;
  res = des3_derivekey(handle, SHISHI_DERIVEKEYMODE_INTEGRITY,
		       SHISHI_KEYUSAGE_ENCASREPPART, key, 24,
		       derivedkey, &derivedkeylen);
  if (res != SHISHI_OK)
    return res;


  res = des3_cbc_sha1_kd_verify (handle, out, outlen, derivedkey);
  if (res != SHISHI_OK)
    {
      shishi_error_set (handle, "verify failed");
      return res;
    }

  return res;
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
		    char random[168 / 8], char key[3 * 8])
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
		    char *string,
		    int stringlen,
		    char *salt,
		    int saltlen, 
		    char *parameter,
		    char outkey[3 * 8])
{
  char *s;
  int n_s;
  int odd;
  char key[3 * 8];
  char nfold[168 / 8];
  int i, j;
  char temp, temp2;
  int res;

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

  res = des3_random_to_key (handle, nfold, key);
  if (res != SHISHI_OK)
    return res;

  res = shishi_dk (handle, SHISHI_DES3_CBC_HMAC_SHA1_KD,
		   key, 3 * 8,
		   "kerberos", strlen ("kerberos"), outkey, 3 * 8);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}
