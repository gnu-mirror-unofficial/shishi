/* crypto-rc4.c	draft-brezak-win2k-krb-rc4-hmac-04 crypto functions
 * Copyright (C) 2003  Simon Josefsson
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
rc4_hmac_encrypt (Shishi * handle,
		  Shishi_key * key,
		  int keyusage,
		  const char *iv,
		  size_t ivlen,
		  char **ivout, size_t * ivoutlen,
		  const char *in, size_t inlen,
		  char **out, size_t * outlen)
{
#if 0
  char L40[14] = "fortybits";
  char SK = "signaturekey";
  char T[4];

  T[0] = keyusage & 0xFF;
  T[1] = (keyusage >> 8) & 0xFF;
  T[2] = (keyusage >> 16) & 0xFF;
  T[3] = (keyusage >> 24) & 0xFF;

  if (shishi_key_type (key) == SHISHI_RC4_HMAC_EXP)
    {
      memcpy(L40 + 10, T, 4);
      HMAC (K, L40, 10 + 4, K1);
    }
  else
    {
      HMAC (K, &T, 4, K1);
    }
  memcpy (K2, K1, 16);
  if (export) memset (K1+7, 0xAB, 9);

  nonce (edata.Confounder, 8);
  memcpy (edata.Data, data);

  edata.Checksum = HMAC (K2, edata);
  K3 = HMAC (K1, edata.Checksum);

  RC4 (K3, edata.Confounder);
  RC4 (K3, data.Data);
#endif

  return SHISHI_OK;
}

static int
rc4_hmac_decrypt (Shishi * handle,
		  Shishi_key * key,
		  int keyusage,
		  const char *iv,
		  size_t ivlen,
		  char **ivout, size_t * ivoutlen,
		  const char *in, size_t inlen,
		  char **out, size_t * outlen)
{
  return SHISHI_OK;
}

static int
rc4_hmac_exp_encrypt (Shishi * handle,
		  Shishi_key * key,
		  int keyusage,
		  const char *iv,
		  size_t ivlen,
		  char **ivout, size_t * ivoutlen,
		  const char *in, size_t inlen,
		  char **out, size_t * outlen)
{
}

static int
rc4_hmac_exp_decrypt (Shishi * handle,
		  Shishi_key * key,
		  int keyusage,
		  const char *iv,
		  size_t ivlen,
		  char **ivout, size_t * ivoutlen,
		  const char *in, size_t inlen,
		  char **out, size_t * outlen)
{
}

#define RC4_HMAC_CKSUM_KEY_DERIVE_CONSTANT "signaturekey"

static int
rc4_hmac_md5_checksum (Shishi * handle,
		       Shishi_key * key,
		       int keyusage,
		       int cksumtype,
		       char *in, size_t inlen,
		       char **out, size_t * outlen)
{

#if USE_GCRYPT
  gcry_md_hd_t mdh, mdh2;
  int halg = GCRY_MD_MD5;
  size_t hlen = gcry_md_get_algo_dlen (halg);
  unsigned char *hash;
  gpg_error_t err;
  char T[4];

  T[0] = keyusage & 0xFF;
  T[1] = (keyusage >> 8) & 0xFF;
  T[2] = (keyusage >> 16) & 0xFF;
  T[3] = (keyusage >> 24) & 0xFF;

  err = gcry_md_open (&mdh, halg, GCRY_MD_FLAG_HMAC);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "Libgcrypt md open failed");
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  err = gcry_md_setkey (mdh, shishi_key_value (key), shishi_key_length (key));
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "Libgcrypt md setkey failed");
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  gcry_md_write (mdh, RC4_HMAC_CKSUM_KEY_DERIVE_CONSTANT,
		 strlen (RC4_HMAC_CKSUM_KEY_DERIVE_CONSTANT) + 1);

  err = gcry_md_open (&mdh2, halg, GCRY_MD_FLAG_HMAC);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "Libgcrypt md open failed");
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  err = gcry_md_setkey (mdh2, gcry_md_read (mdh, halg), hlen);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf (handle, "Libgcrypt md setkey failed");
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  gcry_md_close (mdh);

  gcry_md_write (mdh2, T, 4);
  gcry_md_write (mdh2, in, inlen);

  hash = gcry_md_read (mdh2, halg);
  if (hash == NULL)
    {
      shishi_error_printf (handle, "Libgcrypt failed to compute hash");
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  *outlen = hlen;
  *out = xmemdup (*out, hash, *outlen);

  gcry_md_close (mdh2);
#else
  struct hmac_md5_ctx ctx;
  char Ksign[MD5_DIGEST_SIZE];
  char T[4];

  T[0] = keyusage & 0xFF;
  T[1] = (keyusage >> 8) & 0xFF;
  T[2] = (keyusage >> 16) & 0xFF;
  T[3] = (keyusage >> 24) & 0xFF;

  hmac_md5_set_key (&ctx, shishi_key_length (key), shishi_key_value (key));
  hmac_md5_update (&ctx, strlen(RC4_HMAC_CKSUM_KEY_DERIVE_CONSTANT) + 1,
		   RC4_HMAC_CKSUM_KEY_DERIVE_CONSTANT);
  hmac_md5_digest (&ctx, MD5_DIGEST_SIZE, Ksign);

  hmac_md5_set_key (&ctx, MD5_DIGEST_SIZE, Ksign);

  hmac_md5_update (&ctx, 4, T);
  hmac_md5_update (&ctx, inlen, in);

  *outlen = MD5_DIGEST_SIZE;
  *out = xmalloc (*outlen);

  hmac_md5_digest (&ctx, *outlen, *out);
#endif
  return SHISHI_OK;
}

static int
rc4_hmac_random_to_key (Shishi * handle,
			const char *random, size_t randomlen,
			Shishi_key * outkey)
{
  if (randomlen != shishi_key_length (outkey))
    {
      shishi_error_printf (handle, "RC4 random to key caller error");
      return SHISHI_CRYPTO_ERROR;
    }

  shishi_key_value_set (outkey, random);

  return SHISHI_OK;
}

static int
rc4_hmac_string_to_key (Shishi * handle,
			const char *string,
			size_t stringlen,
			const char *salt,
			size_t saltlen,
			const char *parameter,
			Shishi_key * outkey)
{
#ifdef USE_GCRYPT
  char *hash;
  gcry_md_hd_t hd;
  size_t i;

  gcry_md_open (&hd, GCRY_MD_MD4, 0);
  if (!hd)
    return SHISHI_CRYPTO_INTERNAL_ERROR;

  for (i = 0; i < stringlen; i++)
    {
      gcry_md_write (hd, &string[i], 1);
      gcry_md_write (hd, "", 1);
    }
  hash = gcry_md_read (hd, GCRY_MD_MD4);
  if (hash == NULL)
    {
      shishi_error_printf (handle, "Libgcrypt failed to compute hash");
      return SHISHI_CRYPTO_INTERNAL_ERROR;
    }

  shishi_key_value_set (outkey, hash);

  gcry_md_close (hd);
#else
  struct md4_ctx md4;
  char digest[MD4_DIGEST_SIZE];
  size_t i;

  md4_init (&md4);
  for (i = 0; i < stringlen; i++)
    {
      md4_update (&md4, 1, &string[i]);
      md4_update (&md4, 1, "");
    }
  md4_digest (&md4, sizeof (digest), digest);

  shishi_key_value_set (outkey, digest);
#endif
  return SHISHI_OK;
}
