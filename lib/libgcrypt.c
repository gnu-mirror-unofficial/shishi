/* libgcrypt.c --- Shishi crypto wrappers around Libgcrypt.
 * Copyright (C) 2002, 2003, 2004  Simon Josefsson
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
 */

/* Note: This file is only built if Shishi uses Libgcrypt. */

#include "internal.h"
#include "crypto.h"

#include <gcrypt.h>

/* Refer to nettle.c for documentation. */

int
_shishi_crypto_init (Shishi * handle)
{
  gcry_error_t err;

  err = gcry_control (GCRYCTL_ANY_INITIALIZATION_P);
  if (err == GPG_ERR_NO_ERROR)
    {
      if (gcry_check_version (GCRYPT_VERSION) == NULL)
	{
	  shishi_warn (handle, "gcry_check_version(%s) failed: %s",
		       GCRYPT_VERSION, gcry_check_version (NULL));
	  return SHISHI_CRYPTO_INTERNAL_ERROR;
	}

      err = gcry_control (GCRYCTL_DISABLE_SECMEM, NULL, 0);
      if (err != GPG_ERR_NO_ERROR)
	{
	  shishi_warn (handle, "gcry_control (GCRYCTL_DISABLE_SECMEM)"
		       " failed: %s", gcry_strerror (err));
	  return SHISHI_CRYPTO_INTERNAL_ERROR;
	}

      err = gcry_control (GCRYCTL_INITIALIZATION_FINISHED, NULL, 0);
      if (err != GPG_ERR_NO_ERROR)
	{
	  shishi_warn (handle,
		       "gcry_control (GCRYCTL_INITIALIZATION_FINISHED)"
		       " failed: %s", gcry_strerror (err));
	  return SHISHI_CRYPTO_INTERNAL_ERROR;
	}
    }

  return SHISHI_OK;
}

int
shishi_randomize (Shishi * handle, int strong, void *data, size_t datalen)
{
  if (strong)
    gcry_randomize (data, datalen, GCRY_VERY_STRONG_RANDOM);
  else
    gcry_randomize (data, datalen, GCRY_STRONG_RANDOM);
  return SHISHI_OK;
}

int
shishi_crc (Shishi * handle, const char *in, size_t inlen, char *out[4])
{
  gcry_md_hd_t hd;
  gpg_error_t err;
  unsigned char *p;

  err = gcry_md_open (&hd, GCRY_MD_CRC32_RFC1510, 0);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "Libgcrypt cannot open CRC handle");
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  gcry_md_write (hd, in, inlen);

  p = gcry_md_read (hd, GCRY_MD_CRC32_RFC1510);
  if (p == NULL)
    {
      shishi_error_printf (handle, "Libgcrypt failed to compute hash");
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  *out = xmalloc (4);
  /* XXX */
  (*out)[0] = p[3];
  (*out)[1] = p[2];
  (*out)[2] = p[1];
  (*out)[3] = p[0];

  gcry_md_close (hd);

  return SHISHI_OK;
}

int
shishi_md4 (Shishi * handle, const char *in, size_t inlen, char *out[16])
{
  gcry_md_hd_t hd;
  gpg_error_t err;
  unsigned char *p;

  err = gcry_md_open (&hd, GCRY_MD_MD4, 0);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "Libgcrypt cannot open MD4 handle");
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  gcry_md_write (hd, in, inlen);

  p = gcry_md_read (hd, GCRY_MD_MD4);
  if (p == NULL)
    {
      shishi_error_printf (handle, "Libgcrypt failed to compute hash");
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  *out = xmemdup (p, gcry_md_get_algo_dlen (GCRY_MD_MD4));

  gcry_md_close (hd);

  return SHISHI_OK;
}

int
shishi_md5 (Shishi * handle, const char *in, size_t inlen, char *out[16])
{
  gcry_md_hd_t hd;
  gpg_error_t err;
  unsigned char *p;

  err = gcry_md_open (&hd, GCRY_MD_MD5, 0);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "Libgcrypt cannot open MD5 handle");
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  gcry_md_write (hd, in, inlen);

  p = gcry_md_read (hd, GCRY_MD_MD5);
  if (p == NULL)
    {
      shishi_error_printf (handle, "Libgcrypt failed to compute hash");
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  *out = xmemdup (p, gcry_md_get_algo_dlen (GCRY_MD_MD5));

  gcry_md_close (hd);

  return SHISHI_OK;
}

int
shishi_hmac_md5 (Shishi * handle,
		 const char *key, size_t keylen,
		 const char *in, size_t inlen, char *outhash[16])
{
  gcry_md_hd_t mdh;
  size_t hlen = gcry_md_get_algo_dlen (GCRY_MD_MD5);
  unsigned char *hash;
  gpg_error_t err;

  err = gcry_md_open (&mdh, GCRY_MD_MD5, GCRY_MD_FLAG_HMAC);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "Libgcrypt hmac md open failed");
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  err = gcry_md_setkey (mdh, key, keylen);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "Libgcrypt md setkey failed");
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  gcry_md_write (mdh, in, inlen);

  hash = gcry_md_read (mdh, GCRY_MD_MD5);
  if (hash == NULL)
    {
      shishi_error_printf (handle, "Libgcrypt failed to compute hash");
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  *outhash = xmemdup (hash, hlen);

  gcry_md_close (mdh);

  return SHISHI_OK;
}

int
shishi_hmac_sha1 (Shishi * handle,
		  const char *key, size_t keylen,
		  const char *in, size_t inlen, char *outhash[20])
{
  gcry_md_hd_t mdh;
  size_t hlen = gcry_md_get_algo_dlen (GCRY_MD_SHA1);
  unsigned char *hash;
  gpg_error_t err;

  err = gcry_md_open (&mdh, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "Libgcrypt hmac md open failed");
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  err = gcry_md_setkey (mdh, key, keylen);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "Libgcrypt md setkey failed");
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  gcry_md_write (mdh, in, inlen);

  hash = gcry_md_read (mdh, GCRY_MD_SHA1);
  if (hash == NULL)
    {
      shishi_error_printf (handle, "Libgcrypt failed to compute hash");
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  *outhash = xmemdup (hash, hlen);

  gcry_md_close (mdh);

  return SHISHI_OK;
}

int
shishi_des_cbc_mac (Shishi * handle,
		    const char key[8],
		    const char iv[8],
		    const char *in, size_t inlen, char *out[8])
{
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

  err = gcry_cipher_setiv (ch, iv, 8);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "DES setiv failed");
      shishi_error_set (handle, gpg_strerror (err));
      goto done;
    }

  *out = xmalloc (8);

  err = gcry_cipher_encrypt (ch, *out, 8, in, inlen);
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
}

static int
libgcrypt_dencrypt (Shishi * handle, int algo, int flags, int mode,
		    int decryptp,
		    const char *key, size_t keylen,
		    const char *iv,
		    char **ivout, const char *in, size_t inlen, char **out)
{
  size_t ivlen = gcry_cipher_get_algo_blklen (algo);
  gcry_cipher_hd_t ch;
  gpg_error_t err;

  err = gcry_cipher_open (&ch, algo, mode, flags);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "Libgcrypt cipher open failed");
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  err = gcry_cipher_setkey (ch, key, keylen);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "Libgcrypt setkey failed");
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  err = gcry_cipher_setiv (ch, iv, ivlen);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "Libgcrypt setiv failed");
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  *out = xmalloc (inlen);

  if (decryptp)
    err = gcry_cipher_decrypt (ch, (unsigned char *) *out, inlen,
			       (const unsigned char *) in, inlen);
  else
    err = gcry_cipher_encrypt (ch, (unsigned char *) *out, inlen,
			       (const unsigned char *) in, inlen);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "Libgcrypt ciphering failed");
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  if (ivout)
    {
      size_t ivdiff, ivpos = 0;

      *ivout = xmalloc (ivlen);

      if (flags & GCRY_CIPHER_CBC_CTS)
	{
	  /* XXX what is the output iv for CBC-CTS mode?
	     but is this value useful at all for that mode anyway?
	     Mostly it is DES apps that want the updated iv, so this is ok. */

	  if (inlen % ivlen)
	    ivdiff = ivlen + inlen % ivlen;
	  else
	    ivdiff = ivlen + ivlen;

	  if (inlen >= ivdiff)
	    ivpos = inlen - ivdiff;
	}
      else
	ivpos = inlen - ivlen;

      if (decryptp)
	memcpy (*ivout, in + ivpos, inlen >= ivlen ? ivlen : inlen);
      else
	memcpy (*ivout, *out + ivpos, inlen >= ivlen ? ivlen : inlen);
    }

  gcry_cipher_close (ch);

  return SHISHI_OK;
}

/* BEGIN: Taken from Nettle arcfour.h and arcfour.c */
struct arcfour_ctx
{
  uint8_t S[256];
  uint8_t i;
  uint8_t j;
};

#define SWAP(a,b) do { int _t = a; a = b; b = _t; } while(0)

static void
arcfour_set_key (struct arcfour_ctx *ctx,
		 unsigned length, const uint8_t * key)
{
  unsigned i, j, k;

  /* Initialize context */
  for (i = 0; i < 256; i++)
    ctx->S[i] = i;

  for (i = j = k = 0; i < 256; i++)
    {
      j += ctx->S[i] + key[k];
      j &= 0xff;
      SWAP (ctx->S[i], ctx->S[j]);
      /* Repeat key as needed */
      k = (k + 1) % length;
    }
  ctx->i = ctx->j = 0;
}

static void
arcfour_crypt (struct arcfour_ctx *ctx,
	       unsigned length, uint8_t * dst, const uint8_t * src)
{
  register uint8_t i, j;

  i = ctx->i;
  j = ctx->j;
  while (length--)
    {
      i++;
      i &= 0xff;
      j += ctx->S[i];
      j &= 0xff;
      SWAP (ctx->S[i], ctx->S[j]);
      *dst++ = *src++ ^ ctx->S[(ctx->S[i] + ctx->S[j]) & 0xff];
    }
  ctx->i = i;
  ctx->j = j;
}

/* END: Taken from Nettle arcfour.h and arcfour.c */

int
shishi_arcfour (Shishi * handle, int decryptp,
		const char *key, size_t keylen,
		const char iv[258], char *ivout[258],
		const char *in, size_t inlen, char **out)
{
  struct arcfour_ctx ctx;

  /* Same as in nettle.c.  The reason for all this is that libgcrypt
   * does not export any API to extract the ARCFOUR S-BOX, which we
   * need. */

  *out = xmalloc (inlen);

  if (iv)
    memcpy (&ctx, iv, sizeof (ctx));
  else
    arcfour_set_key (&ctx, keylen, key);

  arcfour_crypt (&ctx, inlen, *out, in);

  if (ivout)
    {
      *ivout = xmalloc (sizeof (ctx));
      memcpy (*ivout, &ctx, sizeof (ctx));
    }

  return SHISHI_OK;
}

int
shishi_des (Shishi * handle, int decryptp,
	    const char key[8],
	    const char iv[8],
	    char *ivout[8], const char *in, size_t inlen, char **out)
{
  return libgcrypt_dencrypt (handle, GCRY_CIPHER_DES, 0, GCRY_CIPHER_MODE_CBC,
			     decryptp, key, 8, iv, ivout, in, inlen, out);
}

int
shishi_3des (Shishi * handle, int decryptp,
	     const char key[24],
	     const char iv[8],
	     char *ivout[8], const char *in, size_t inlen, char **out)
{
  return libgcrypt_dencrypt (handle, GCRY_CIPHER_3DES, 0,
			     GCRY_CIPHER_MODE_CBC, decryptp, key, 24, iv,
			     ivout, in, inlen, out);
}

int
shishi_aes_cts (Shishi * handle, int decryptp,
		const char *key, size_t keylen,
		const char iv[16],
		char *ivout[16], const char *in, size_t inlen, char **out)
{
  return libgcrypt_dencrypt (handle, GCRY_CIPHER_AES, GCRY_CIPHER_CBC_CTS,
			     GCRY_CIPHER_MODE_CBC, decryptp,
			     key, keylen, iv, ivout, in, inlen, out);
}
