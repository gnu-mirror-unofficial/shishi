/* crypto-md.c	DES crypto functions
 * Copyright (C) 2002, 2003  Simon Josefsson
 * Copyright (C) 2003  Nicolas Pouvesle
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
md4_checksum (Shishi * handle,
	      Shishi_key * key,
	      int keyusage,
	      int cksumtype,
	      const char *in, size_t inlen, char **out, size_t * outlen)
{
#ifdef USE_GCRYPT
  char *hash;
  gcry_md_hd_t hd;

  gcry_md_open (&hd, GCRY_MD_MD4, 0);
  if (!hd)
    return SHISHI_CRYPTO_INTERNAL_ERROR;

  gcry_md_write (hd, in, inlen);
  hash = gcry_md_read (hd, GCRY_MD_MD4);
  if (hash == NULL)
    {
      shishi_error_printf (handle, "Libgcrypt failed to compute hash");
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  *outlen = gcry_md_get_algo_dlen (GCRY_MD_MD4);
  *out = xmemdup (*out, hash, *outlen);

  gcry_md_close (hd);
#else
  struct md4_ctx md4;
  char digest[MD4_DIGEST_SIZE];
  int rc;

  md4_init (&md4);
  md4_update (&md4, inlen, in);
  md4_digest (&md4, sizeof (digest), digest);

  *outlen = MD4_DIGEST_SIZE;
  *out = xmemdup (*out, digest, *outlen);
#endif
  return SHISHI_OK;
}

static int
md5_checksum (Shishi * handle,
	      Shishi_key * key,
	      int keyusage,
	      int cksumtype,
	      const char *in, size_t inlen, char **out, size_t * outlen)
{
#ifdef USE_GCRYPT
  char *hash;
  gcry_md_hd_t hd;

  gcry_md_open (&hd, GCRY_MD_MD5, 0);
  if (!hd)
    return SHISHI_CRYPTO_INTERNAL_ERROR;

  gcry_md_write (hd, in, inlen);
  hash = gcry_md_read (hd, GCRY_MD_MD5);
  if (hash == NULL)
    {
      shishi_error_printf (handle, "Libgcrypt failed to compute hash");
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  *outlen = gcry_md_get_algo_dlen (GCRY_MD_MD5);
  *out = xmemdup (*out, hash, *outlen);

  gcry_md_close (hd);
#else
  struct md5_ctx md5;
  char digest[MD5_DIGEST_SIZE];
  int rc;

  md5_init (&md5);
  md5_update (&md5, inlen, in);
  md5_digest (&md5, sizeof (digest), digest);

  *outlen = MD5_DIGEST_SIZE;
  *out = xmemdup (*out, digest, *outlen);
#endif
  return SHISHI_OK;
}
