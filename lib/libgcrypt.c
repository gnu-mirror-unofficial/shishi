/* libgcrypt.c   shishi crypto wrappers around libgcrypt.
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
 */

/* Note: This file is only built if Shishi uses Libgcrypt. */

#include "internal.h"

#include <gcrypt.h>

int
shishi_crypto_init (void)
{
  if (gcry_control (GCRYCTL_ANY_INITIALIZATION_P) == 0)
    {
      if (gcry_check_version (GCRYPT_VERSION) == NULL)
	return SHISHI_CRYPTO_INTERNAL_ERROR;
      if (gcry_control (GCRYCTL_DISABLE_SECMEM, NULL, 0) != GPG_ERR_NO_ERROR)
	return SHISHI_CRYPTO_INTERNAL_ERROR;
      if (gcry_control (GCRYCTL_INITIALIZATION_FINISHED,
			NULL, 0) != GPG_ERR_NO_ERROR)
	return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  return SHISHI_OK;
}

int
shishi_hmac_sha1 (Shishi * handle,
		  const char *key, size_t keylen,
		  const char *in, size_t inlen,
		  char **outhash, size_t * outhashlen)
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

  *outhashlen = hlen;
  *outhash = xmemdup (*outhash, hash, *outhashlen);

  gcry_md_close (mdh);

  return SHISHI_OK;
}

static int
libgcrypt_dencrypt (Shishi * handle, int algo, int flags, int decryptp,
		    const char *key, size_t keylen,
		    const char *iv, size_t ivlen,
		    char **ivout, size_t * ivoutlen,
		    const char *in, size_t inlen,
		    char **out, size_t * outlen)
{
  gcry_cipher_hd_t ch;
  gpg_error_t err;
  int mode = GCRY_CIPHER_MODE_CBC;

  *outlen = inlen;

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

  *out = xmalloc (*outlen);

  if (decryptp)
    err = gcry_cipher_decrypt (ch, (unsigned char *) *out, *outlen,
			       (const unsigned char *) in, inlen);
  else
    err = gcry_cipher_encrypt (ch, (unsigned char *) *out, *outlen,
			       (const unsigned char *) in, inlen);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "Libgcrypt ciphering failed");
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  if (ivout && ivoutlen)
    {
      *ivoutlen = gcry_cipher_get_algo_blklen (alg);
      *ivout = xmalloc (*ivoutlen);
      if (decryptp)
	memcpy (*ivout, in + inlen - *ivoutlen, *ivoutlen);
      else
	/* XXX what is the output iv for CBC-CTS mode?
	   but is this value useful at all for that mode anyway?
	   Mostly it is DES apps that want the updated iv, so this is ok. */
	memcpy (*ivout, *out + *outlen - *ivoutlen, *ivoutlen);
    }

  gcry_cipher_close (ch);

  return SHISHI_OK;
}

int
shishi_des (Shishi * handle, int decryptp,
	    const char *key, size_t keylen,
	    const char *iv, size_t ivlen,
	    char **ivout, size_t * ivoutlen,
	    const char *in, size_t inlen,
	    char **out, size_t * outlen)
{
  return shishi_libgcrypt (handle, GCRY_CIPHER_DES, 0,
			   decryptp,
			   key, keylen,
			   iv, ivlen,
			   ivout, ivoutlen,
			   in, inlen,
			   out, outlen);
}

int
shishi_3des (Shishi * handle, int decryptp,
	     const char *key, size_t keylen,
	     const char *iv, size_t ivlen,
	     char **ivout, size_t * ivoutlen,
	     const char *in, size_t inlen,
	     char **out, size_t * outlen)
{
  return shishi_libgcrypt (handle, GCRY_CIPHER_3DES, 0,
			   decryptp,
			   key, keylen,
			   iv, ivlen,
			   ivout, ivoutlen,
			   in, inlen,
			   out, outlen);
}

int
shishi_aes (Shishi * handle, int decryptp,
	    const char *key, size_t keylen,
	    const char *iv, size_t ivlen,
	    char **ivout, size_t * ivoutlen,
	    const char *in, size_t inlen,
	    char **out, size_t * outlen)
{
  return shishi_libgcrypt (handle, GCRY_CIPHER_AES, GCRY_CIPHER_CBC_CTS,
			   decryptp,
			   key, keylen,
			   iv, ivlen,
			   ivout, ivoutlen,
			   in, inlen,
			   out, outlen);
}
