/* crypto-ctx.c --- Shishi crypto context self tests.
 * Copyright (C) 2002, 2003, 2006, 2007, 2008  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#include "utils.c"

static const char rnd[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz0123456789";

static const char iv[] =
  "0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

const char *in =
  "abcdefghijklmnopqrstuvwxyz01234567890123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

struct tv
{
  int etype;
  size_t start;
  size_t step;
  size_t len;
};
const struct tv tv[] = {
  {SHISHI_DES_CBC_CRC, 4, 8, 68},
  {SHISHI_DES_CBC_MD4, 0, 8, 72},
  {SHISHI_DES_CBC_MD5, 0, 8, 72},
  {SHISHI_DES_CBC_NONE, 8, 8, 72},
  {SHISHI_DES3_CBC_NONE, 8, 8, 72},
  /* XXX following three doesn't use start=0 because of a weird
     realloc(0,0) problem */
  {SHISHI_DES3_CBC_HMAC_SHA1_KD, 8, 8, 72},
  {SHISHI_AES128_CTS_HMAC_SHA1_96, 1, 1, 72},
  {SHISHI_AES256_CTS_HMAC_SHA1_96, 1, 1, 72},
  {SHISHI_ARCFOUR_HMAC, 0, 1, 72},
  {SHISHI_ARCFOUR_HMAC_EXP, 0, 1, 72},
  {0, 0, 0, 0}
};

void
test (Shishi * handle)
{
  Shishi_crypto *ctx, *ctx2;
  Shishi_key *key;
  char *out, *out2;
  size_t i, j;
  size_t len, len2;
  const struct tv *tvp;
  int err;

  if (debug)
    shishi_cfg (handle, strdup ("verbose-crypto"));

  for (i = 0; tvp = &tv[i], tvp->etype; i++)
    {
      len = shishi_cipher_randomlen (tvp->etype);
      if (len == (size_t) -1)
	{
	  fail ("shishi_cipher_randomlen(%d) failed: %d\n", tvp->etype, len);
	  continue;
	}

      err = shishi_key_from_random (handle, tvp->etype, rnd, len, &key);
      if (err)
	{
	  fail ("shishi_key_from_random(%d) failed (%d)\n", tvp->etype, err);
	  continue;
	}

      len = shishi_cipher_blocksize (tvp->etype);
      if (len == (size_t) -1)
	{
	  fail ("shishi_cipher_blocksize (%d) failed: %d\n", tvp->etype, len);
	  continue;
	}

      if (tvp->etype == SHISHI_ARCFOUR_HMAC ||
	  tvp->etype == SHISHI_ARCFOUR_HMAC_EXP)
	{
	  /* For ARCFOUR, IV is internal S-BOX, not of blocksize length.
	     We probably should clean this up somehow... */
	  ctx = shishi_crypto (handle, key, SHISHI_KEYUSAGE_ENCASREPPART,
			       tvp->etype, NULL, 0);
	  ctx2 = shishi_crypto (handle, key, SHISHI_KEYUSAGE_ENCASREPPART,
				tvp->etype, NULL, 0);
	}
      else
	{
	  ctx = shishi_crypto (handle, key, SHISHI_KEYUSAGE_ENCASREPPART,
			       tvp->etype, iv, len);
	  ctx2 = shishi_crypto (handle, key, SHISHI_KEYUSAGE_ENCASREPPART,
				tvp->etype, iv, len);
	}
      if (!ctx)
	{
	  fail ("shishi_crypto(%d) failed\n", tvp->etype);
	  continue;
	}
      if (!ctx2)
	{
	  fail ("shishi_crypto(%d) failed (2)\n", tvp->etype);
	  continue;
	}

      for (j = tvp->start; j < tvp->len; j += tvp->step)
	{
	  int ok;

	  err = shishi_crypto_encrypt (ctx, in, j, &out, &len);
	  if (err)
	    {
	      fail ("shishi_crypto_encrypt(etype=%d, len=%d) failed (%d)\n",
		    tvp->etype, j, err);
	      continue;
	    }

	  err = shishi_crypto_decrypt (ctx2, out, len, &out2, &len2);
	  if (err)
	    {
	      fail ("shishi_crypto_decrypt(etype=%d, len=%d) failed (%d)\n",
		    tvp->etype, j, err);
	      continue;
	    }

	  free (out);

	  ok = len2 != j || memcmp (out2, in, len2) != 0;

	  free (out2);

	  if (ok)
	    {
	      puts ("expected");
	      hexprint (in, j);
	      puts ("computed");
	      hexprint (out2, len2);
	      fail ("shishi_crypto_encrypt (in1, %d) failed\n", tvp->etype);
	      continue;
	    }
	  success ("shishi_crypto_encrypt/decrypt(etype=%d, len=%d) OK\n",
		   tvp->etype, j);
	}

      shishi_crypto_close (ctx);
      shishi_crypto_close (ctx2);
      shishi_key_done (key);

      success ("shishi_crypto_encrypt/decrypt(etype=%d) OK\n", tvp->etype);
    }
}
