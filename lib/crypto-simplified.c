/* crypto-simplified.c	Simplified crypto profile functions
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

typedef enum {
  SHISHI_DERIVEKEYMODE_CHECKSUM,
  SHISHI_DERIVEKEYMODE_PRIVACY,
  SHISHI_DERIVEKEYMODE_INTEGRITY
} Shishi_derivekeymode;

#define MAX_DERIVEDKEY_LEN 50

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
      
      res = shishi_dk (handle, keytype, key, keylen,  constant, 5, 
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
  char buffer[BUFSIZ];
  int buflen;
  int res;

  if (keyusage != 0)
    {
      puts("urkel keyusage");
      buflen = sizeof (buffer);
      res = des3_cbc_sha1_kd_checksum (handle, buffer, &buflen, in, inlen);
      memcpy (buffer + buflen, in, inlen);
      buflen += inlen;
      res = lowlevel_dencrypt (handle, keytype, out, outlen, buffer, buflen, 
			       key, keylen, 0);
    }
  else
    {
      res = lowlevel_dencrypt (handle, keytype, out, outlen, in, inlen, 
			       key, keylen, 0);
      if (res != SHISHI_OK)
	{
	  shishi_error_set (handle, "encrypt failed");
	  return res;
	}
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
  char derivedkey[50];
  int derivedkeylen = 50;

  if (keyusage)
    {
      res = simplified_derivekey(handle, SHISHI_DERIVEKEYMODE_PRIVACY, 
				 keyusage, keytype, key, keylen,
				 derivedkey, &derivedkeylen);
      if (res != SHISHI_OK)
	return res;

      res = lowlevel_dencrypt (handle, keytype, out, outlen, in, inlen - 20, 
			       derivedkey, derivedkeylen, 1);
      if (res != SHISHI_OK)
	{
	  shishi_error_set (handle, "decrypt failed");
	  return res;
	}
      
      derivedkeylen = MAX_DERIVEDKEY_LEN;
      res = simplified_derivekey(handle, SHISHI_DERIVEKEYMODE_INTEGRITY,
				 keyusage, keytype, key, keylen,
				 derivedkey, &derivedkeylen);
      if (res != SHISHI_OK)
	return res;
      
      
      res = lowlevel_verify (handle, keytype, out, outlen, in, inlen,
			     derivedkey, derivedkeylen);
      if (res != SHISHI_OK)
	{
	  shishi_error_set (handle, "verify failed");
	  return res;
	}
    }
  else
    {
      res = lowlevel_dencrypt (handle, keytype, out, outlen, in, inlen, 
			       key, keylen, 1);
      if (res != SHISHI_OK)
	{
	  shishi_error_set (handle, "decrypt failed");
	  return res;
	}
    }

  return res;
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
  int blocksize = _shishi_cipher_blocksize (etype);
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
      printf ("\t ;; possibly nfolded constant (length %d):\n", 8);
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
