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

static void
escapeprint (unsigned char *str, int len)
{
  int i;

  printf ("\t ;; `");
  for (i = 0; i < len; i++)
    if ((str[i] >= 'A' && str[i] <= 'Z') ||
	(str[i] >= 'a' && str[i] <= 'z') ||
	(str[i] >= '0' && str[i] <= '9') || str[i] == '.')
      printf ("%c", str[i]);
    else
      printf ("\\x%02x", str[i]);
  printf ("' (length %d bytes)\n", len);
}

static void
hexprint (unsigned char *str, int len)
{
  int i;

  printf ("\t ;; ");
  for (i = 0; i < len; i++)
    {
      printf ("%02x ", str[i]);
      if ((i + 1) % 8 == 0)
	printf (" ");
      if ((i + 1) % 16 == 0 && i + 1 < len)
	printf ("\n\t ;; ");
    }
}

static void
binprint (unsigned char *str, int len)
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
bin7print (unsigned char *str, int len)
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
gcrypt (Shishi * handle,
	int alg,
	unsigned char *out,
	int *outlen,
	unsigned char *in,
	int inlen, unsigned char *key, int keylen, int direction)
{
  int res;
  GCRY_CIPHER_HD ch;
  int j;
  unsigned char iv[8];
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

  memset (iv, 0, 8);
  res = gcry_cipher_setiv (ch, iv, 8);
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
	      unsigned char *out,
	      int *outlen, unsigned char *in, int inlen, unsigned char *key)
{
  if (*outlen < inlen)
    return !SHISHI_OK;

  memcpy (out, in, inlen);
  *outlen = inlen;

  return SHISHI_OK;
}

static int
null_decrypt (Shishi * handle,
	      unsigned char *out,
	      int *outlen, unsigned char *in, int inlen, unsigned char *key)
{
  if (*outlen < inlen)
    return !SHISHI_OK;

  memcpy (out, in, inlen);
  *outlen = inlen;

  return SHISHI_OK;
}

/* DES */

static int
des_encrypt (Shishi * handle,
	     unsigned char *out,
	     int *outlen, unsigned char *in, int inlen, unsigned char key[8])
{
  return gcrypt (handle, GCRY_CIPHER_DES, out, outlen, in, inlen, key, 8, 0);
}

static int
des_decrypt (Shishi * handle,
	     unsigned char *out,
	     int *outlen, unsigned char *in, int inlen, unsigned char key[8])
{
  return gcrypt (handle, GCRY_CIPHER_DES, out, outlen, in, inlen, key, 8, 1);
}

static int
des_crc_verify (Shishi * handle, unsigned char *out, int *outlen)
{
  shishi_error_set (handle, "CRC not implemented");
  return !SHISHI_OK;
}

static int
des_md4_verify (Shishi * handle, unsigned char *out, int *outlen)
{
  shishi_error_set (handle, "MD4 not implemented");
  return !SHISHI_OK;
}

static int
des_md5_verify (Shishi * handle, unsigned char *out, int *outlen)
{
  int res;
  unsigned char md[16];
  GCRY_MD_HD hd;
  unsigned char *p;

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
  if (DEBUGCRYPTO(handle))
    {
      int i;

      for (i = 0; i < 16; i++)
	printf ("%02X ", md[i]);
      printf ("\n");
      for (i = 0; i < 16; i++)
	printf ("%02X ", p[i]);
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
      if (DEBUG(handle))
	printf ("des-cbc-md5 verify fail\n");
      res = !SHISHI_OK;
    }

  gcry_md_close (hd);

  return res;
}
static int
des_md5_checksum (Shishi * handle,
		  unsigned char *out,
		  int *outlen, unsigned char *in, int inlen)
{
  int res;
  unsigned char buffer[BUFSIZ];
  unsigned char confounder[8];
  unsigned char md[16];
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
      unsigned char *p;

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
des_crc_decrypt (Shishi * handle,
		 unsigned char *out,
		 int *outlen,
		 unsigned char *in, int inlen, unsigned char *key)
{
  int res;

  res = des_decrypt (handle, out, outlen, in, inlen, key);
  if (res != SHISHI_OK)
    {
      shishi_error_set (handle, "decrypt failed");
      return res;
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
des_md4_decrypt (Shishi * handle,
		 unsigned char *out,
		 int *outlen,
		 unsigned char *in, int inlen, unsigned char *key)
{
  int res;

  res = des_decrypt (handle, out, outlen, in, inlen, key);
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
		 unsigned char *out,
		 int *outlen,
		 unsigned char *in, int inlen, unsigned char *key)
{
  char buffer[BUFSIZ];
  int buflen;
  int res;

  buflen = sizeof (buffer);
  res = des_md5_checksum (handle, buffer, &buflen, in, inlen);
  memcpy (buffer + buflen, in, inlen);
  buflen += inlen;
  res = des_encrypt (handle, out, outlen, buffer, buflen, key);

  return res;
}

static int
des_md5_decrypt (Shishi * handle,
		 unsigned char *out,
		 int *outlen,
		 unsigned char *in, int inlen, unsigned char *key)
{
  int res;

  res = des_decrypt (handle, out, outlen, in, inlen, key);
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
des_set_odd_key_parity (unsigned char key[8])
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
des_key_correction (Shishi * handle, unsigned char *key)
{
  int res;
  GCRY_CIPHER_HD ch;
  int j;

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
	  if (DEBUGCRYPTO(handle))
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
des_cbc_check (unsigned char key[8], unsigned char *data, int n_data)
{
  GCRY_CIPHER_HD ch;
  int j;
  int res;
  unsigned char ct[1024];
  unsigned char final[2 * 8];
  unsigned char iv[8];

  ch = gcry_cipher_open (GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CBC, 0);
  if (ch == NULL)
    return !SHISHI_OK;

  res = gcry_cipher_setkey (ch, key, 8);
  if (res != GCRYERR_SUCCESS)
    return !SHISHI_OK;

  memset (iv, 0, 8);
  res = gcry_cipher_setiv (ch, key, 8);
  if (res != 0)
    return !SHISHI_OK;

  res = gcry_cipher_encrypt (ch, ct, sizeof (ct), data, n_data);
  if (res != 0)
    return !SHISHI_OK;

  memcpy (key, ct + n_data - 8, 8);

  gcry_cipher_close (ch);

  return SHISHI_OK;
}


static int
des_string_to_key (Shishi * handle,
		   unsigned char *string,
		   int stringlen,
		   unsigned char *salt, int saltlen, unsigned char outkey[8])
{
  unsigned char *s;
  int n_s;
  int odd;
  unsigned char tempkey[8];
  int i, j;
  unsigned char temp, temp2;
  int res;

  if (DEBUGCRYPTO(handle))
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

  if (DEBUGCRYPTO(handle))
    {
      printf ("\t ;; s = pad(string|salt):\n");
      escapeprint (s, n_s);
      hexprint (s, n_s);
      puts ("");
    }

  for (i = 0; i < n_s / 8; i++)
    {
      if (DEBUGCRYPTO(handle))
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

      if (DEBUGCRYPTO(handle))
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
	  if (DEBUGCRYPTO(handle))
	    {
	      printf ("reverse(56bitstring)\n");
	      printf ("\t ;; 56bitstring after reverse\n");
	      bin7print (&s[i * 8], 8);
	      puts ("");
	    }
	}

      odd = !odd;

      if (DEBUGCRYPTO(handle))
	{
	  printf ("odd = ! odd\n");
	  printf ("tempstring = tempstring XOR 56bitstring;\n");
	}

      /* tempkey = tempkey XOR 8byteblock; */
      for (j = 0; j < 8; j++)
	tempkey[j] ^= s[i * 8 + j];

      if (DEBUGCRYPTO(handle))
	{
	  printf ("\t ;; tempstring\n");
	  bin7print (tempkey, 8);
	  puts ("");
	  puts ("");
	}
    }

  for (j = 0; j < 8; j++)
    tempkey[j] = tempkey[j] << 1;

  if (DEBUGCRYPTO(handle))
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

  if (DEBUGCRYPTO(handle))
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

  if (DEBUGCRYPTO(handle))
    {
      printf ("\t ;; key\n");
      escapeprint (tempkey, 8);
      hexprint (tempkey, 8);
      puts ("");
      binprint (tempkey, 8);
      puts ("");
      puts ("");
    }

  memcpy (outkey, tempkey, 8);

  return SHISHI_OK;
}


/* DES3 */

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
	      unsigned char *out,
	      int *outlen,
	      unsigned char *in, int inlen, unsigned char key[3 * 8])
{
  return gcrypt (handle, GCRY_CIPHER_3DES, out, outlen, in, inlen, key, 3 * 8,
		 0);
}

static int
des3_decrypt (Shishi * handle,
	      unsigned char *out,
	      int *outlen,
	      unsigned char *in, int inlen, unsigned char key[3 * 8])
{
  return gcrypt (handle, GCRY_CIPHER_3DES, out, outlen, in, inlen, key, 3 * 8,
		 1);
}

#define DES3_DERIVEKEY_CONSTANTLEN 5

static int
des3_derivekey (Shishi *handle,
		int derivekeymode,
		int keyusage,
		unsigned char *key,
		int keylen,
		unsigned char *derivedkey,
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
			   unsigned char *out,
			   int *outlen, unsigned char *in, int inlen)
{
#if 0
  int res;
  unsigned char buffer[BUFSIZ];
  unsigned char confounder[8];
  unsigned char md[16];
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
      unsigned char *p;

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
			  unsigned char *out,
			  int *outlen,
			  unsigned char *in, int inlen, unsigned char *key)
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
des3_cbc_sha1_kd_verify (Shishi * handle, unsigned char *out, int *outlen,
			 unsigned char *key)
{
  GCRY_MD_HD mdh;
  unsigned char *hash;
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

  printf("hash: ");
  for (i = 0; i < 21; i++)
    printf("%02x", hash[i]);
  printf("\n");

  memmove (out, out + 8, *outlen - 8);
  *outlen -= 8 + 24;
  return SHISHI_OK;
}

static int
des3_cbc_sha1_kd_decrypt (Shishi * handle,
			  unsigned char *out,
			  int *outlen,
			  unsigned char *in, int inlen, unsigned char *key)
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
		    unsigned char random[168 / 8], unsigned char key[3 * 8])
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
		    unsigned char *string,
		    int stringlen,
		    unsigned char *salt,
		    int saltlen, unsigned char outkey[3 * 8])
{
  unsigned char *s;
  int n_s;
  int odd;
  unsigned char key[3 * 8];
  unsigned char nfold[168 / 8];
  int i, j;
  unsigned char temp, temp2;
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


static int
checksum_md5 (Shishi * handle,
	      unsigned char *out, int *outlen, unsigned char *in, int inlen)
{
  int res;
  unsigned char buffer[BUFSIZ];
  unsigned char confounder[8];
  unsigned char md[16];
  GCRY_MD_HD hd;
  int i;

  if (inlen + 8 > BUFSIZ)
    {
      shishi_error_printf (handle, "checksum inbuffer too large");
      return !SHISHI_OK;
    }


  memcpy (buffer + 8, in, inlen);

#if 0
  printf ("cksum in len=%d:", inlen);
  for (i = 0; i < inlen; i++)
    printf ("%02x ", in[i]);
  printf ("\n");
#endif

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
      unsigned char *p;

      gcry_md_write (hd, buffer, inlen + 8);
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

#if 0
  printf ("cksum out: ");
  for (i = 0; i < *outlen; i++)
    printf ("%02X ", out[i]);
  printf ("\n");
#endif

  return SHISHI_OK;
}

/* Generic stuff */

typedef int (*Shishi_random_to_key_function) (Shishi * handle,
					      unsigned char *random,
					      unsigned char *key);

typedef int (*Shishi_string_to_key_function) (Shishi * handle,
					      unsigned char *string,
					      int stringlen,
					      unsigned char *salt,
					      int saltlen,
					      unsigned char *outkey);

typedef int (*Shishi_encrypt_function) (Shishi * handle,
					unsigned char *out,
					int *outlen,
					unsigned char *in,
					int inlen, unsigned char *key);

typedef int (*Shishi_decrypt_function) (Shishi * handle,
					unsigned char *out,
					int *outlen,
					unsigned char *in,
					int inlen, unsigned char *key);

typedef int (*Shishi_derivekey_function) (Shishi * handle,
					  int derivekeymode,
					  int keyusage,
					  unsigned char *key,
					  int keylen,
					  unsigned char *derivedkey,
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
  des_string_to_key
};

cipherinfo des_cbc_md4_info = {
  2,
  "des-cbc-md4",
  8,
  0,
  8,
  8,
  NULL,
  des_string_to_key
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

cipherinfo *ciphers[] = {
  &null_info,
  &des_cbc_crc_info,
  &des_cbc_md4_info,
  &des_cbc_md5_info,
  &des3_cbc_sha1_kd_info
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
 * @random: input array with random data.
 * @randomlen: length of input array with random data.
 * @outkey: output array with key.
 * @outkeylen: on input, holds maximum size of output array, on output
 *             holds actual size of output array.
 * 
 * Convert a string (password) and some salt (realm and principal)
 * into a cryptographic key.
 *
 * If OUTKEY is NULL, this functions only set OUTKEYLEN.  This usage
 * may be used by the caller to allocate the proper buffer size.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_string_to_key (Shishi * handle,
		      int etype,
		      unsigned char *string,
		      int stringlen,
		      unsigned char *salt,
		      int saltlen, unsigned char *outkey, int *outkeylen)
{
  Shishi_string_to_key_function string2key;
  int res;

  if (DEBUGCRYPTO(handle))
    {
      printf ("string_to_key (%s, string, salt)\n",
	      shishi_cipher_name (etype));
      printf ("\t ;; string:\n");
      escapeprint (string, stringlen);
      hexprint (string, stringlen);
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
      res = (*string2key) (handle, string, stringlen, salt, saltlen, outkey);
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
		      unsigned char *random,
		      int randomlen, unsigned char *outkey, int *outkeylen)
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
      shishi_error_printf (handle, "Unsupported string_to_key() etype %d",
			   etype);
      return !SHISHI_OK;
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
		 unsigned char *out,
		 int *outlen,
		 unsigned char *in, int inlen, unsigned char *key, int keylen)
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
    case SHISHI_RSA_MD5_DES:
      if (keylen < 8)
	res = !SHISHI_OK;
      else
	{
	  char buffer[BUFSIZ];
	  int buflen;
	  unsigned char cksumkey[8];
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
			unsigned char *out,
			int *outlen,
			unsigned char *in, int inlen, 
			unsigned char *key, int keylen)
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

      res = shishi_dk (handle, cksumtype, key, keylen, constant, constantlen,
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
		unsigned char *out,
		int *outlen,
		unsigned char *in, int inlen, unsigned char *key, int keylen)
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
		       unsigned char *out,
		       int *outlen,
		       unsigned char *in, int inlen, 
		       unsigned char *key, int keylen)
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
		unsigned char *out,
		int *outlen,
		unsigned char *in, int inlen, unsigned char *key, int keylen)
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
		       unsigned char *out,
		       int *outlen,
		       unsigned char *in, int inlen, 
		       unsigned char *key, int keylen)
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
	       unsigned char *in, int inlen, unsigned char *out, int outlen)
{
  int m = inlen;
  int n = outlen;
  unsigned char *buf = NULL;
  unsigned char *a = NULL;
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

      memcpy ((unsigned char *) &buf[i * m], a, m);
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

      ocadd (out, (unsigned char *) &buf[i * n], out, n);

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
	   unsigned char *key,
	   int keylen,
	   unsigned char *constant,
	   int constantlen,
	   unsigned char *derivedrandom, int derivedrandomlen)
{
  unsigned char cipher[MAX_DR_CONSTANT];
  unsigned char plaintext[MAX_DR_CONSTANT];
  unsigned char nfoldconstant[MAX_DR_CONSTANT];
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
	   unsigned char *key,
	   int keylen,
	   unsigned char *constant,
	   int constantlen, unsigned char *derivedkey, int derivedkeylen)
{
  unsigned char *tmp;
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
