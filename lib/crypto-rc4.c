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
 */

#include "internal.h"

#include "crypto.h"

static int arcfour_keyusage (int keyusage)
{
  /*
   *    1.  AS-REQ PA-ENC-TIMESTAMP padata timestamp, encrypted with
   *    the client key (T=1)
   *    2.  AS-REP Ticket and TGS-REP Ticket (includes TGS session key
   *    or application session key), encrypted with the service key
   *    (T=2)
   *    3.  AS-REP encrypted part (includes TGS session key or
   *    application session key), encrypted with the client key (T=8)
   *    4.  TGS-REQ KDC-REQ-BODY AuthorizationData, encrypted with the
   *    TGS session key (T=4)
   *    5.  TGS-REQ KDC-REQ-BODY AuthorizationData, encrypted with the
   *    TGS authenticator subkey (T=5)
   *    6.  TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator cksum, keyed
   *    with the TGS session key (T=6)
   *    7.  TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
   *    TGS authenticator subkey), encrypted with the TGS session key
   *    (T=7)
   *    8.  TGS-REP encrypted part (includes application session key),
   *    encrypted with the TGS session key (T=8)
   *    9.  TGS-REP encrypted part (includes application session key),
   *    encrypted with the TGS authenticator subkey (T=8)
   *    10.  AP-REQ Authenticator cksum, keyed with the application
   *    session key (T=10)
   *    11.  AP-REQ Authenticator (includes application authenticator
   *    subkey), encrypted with the application session key (T=11)
   *    12.  AP-REP encrypted part (includes application session
   *    subkey), encrypted with the application session key (T=12)
   *    13.  KRB-PRIV encrypted part, encrypted with a key chosen by
   *    the application. Also for data encrypted with GSS Wrap (T=13)
   *    14.  KRB-CRED encrypted part, encrypted with a key chosen by
   *    the application (T=14)
   *    15.  KRB-SAFE cksum, keyed with a key chosen by the
   *    application. Also for data signed in GSS MIC (T=15)
   *
   *    Relative to RFC-1964 key uses:
   *
   *    T = 0 in the generation of sequence number for the MIC token
   *    T = 0 in the generation of sequence number for the WRAP token
   *    T = 0 in the generation of encrypted data for the WRAPPED token
   *
   */

  if (keyusage == 3)
    return 8;
  else if (keyusage == 9)
    return 8;

  return keyusage;
}

static int
arcfour_hmac_encrypt (Shishi * handle,
		  Shishi_key * key,
		  int keyusage,
		  const char *iv,
		  size_t ivlen,
		  char **ivout, size_t * ivoutlen,
		  const char *in, size_t inlen, char **out, size_t * outlen)
{
  int export = shishi_key_type (key) == SHISHI_ARCFOUR_HMAC_EXP;
  int arcfourkeyusage = arcfour_keyusage (keyusage);
  char L40[14] = "fortybits";
  uint8_t T[4];
  char *K1 = NULL;
  char K2[16];
  char *K3 = NULL;
  char *pt = NULL;
  char *cksum = NULL;
  int offset;
  int err;

  T[0] = arcfourkeyusage & 0xFF;
  T[1] = (arcfourkeyusage >> 8) & 0xFF;
  T[2] = (arcfourkeyusage >> 16) & 0xFF;
  T[3] = (arcfourkeyusage >> 24) & 0xFF;

  memcpy (L40 + 10, T, 4);

  if (export)
    offset = 10;
  else
    offset = 0;

  err = shishi_hmac_md5 (handle,
			 shishi_key_value (key), shishi_key_length (key),
			 L40 + offset, 14 - offset, &K1);
  if (err)
    goto done;

  memcpy (K2, K1, 16);
  if (export)
    memset (K1 + 7, 0xAB, 9);

  pt = xmalloc (16 + 8 + inlen);

  memset (pt, 0, 16);
  err = shishi_randomize (handle, 0, pt + 16, 8);
  if (err)
    goto done;
  memcpy (pt + 16 + 8, in, inlen);

  err = shishi_hmac_md5 (handle, K2, 16, pt, 16 + 8 + inlen, &cksum);
  if (err)
    goto done;
  err = shishi_hmac_md5 (handle, K1, 16, cksum, 16, &K3);
  if (err)
    goto done;

  *outlen = 8 + inlen;
  err = shishi_arcfour (handle, 0, K3, 16, pt + 16, 8 + inlen, out);
  if (err)
    goto done;

  memcpy (out, cksum, 16);

  err = SHISHI_OK;

 done:
  free (cksum);
  free (K3);
  free (pt);
  free (K1);
  return err;
}

static int
arcfour_hmac_decrypt (Shishi * handle,
		  Shishi_key * key,
		  int keyusage,
		  const char *iv,
		  size_t ivlen,
		  char **ivout, size_t * ivoutlen,
		  const char *in, size_t inlen, char **out, size_t * outlen)
{
  int export = shishi_key_type (key) == SHISHI_ARCFOUR_HMAC_EXP;
  int arcfourkeyusage = arcfour_keyusage (keyusage);
  char L40[14] = "fortybits";
  uint8_t T[4];
  char *K1 = NULL;
  char K2[16];
  char *K3 = NULL;
  char *pt = NULL;
  char *cksum = NULL;
  int offset;
  int err;

  T[0] = arcfourkeyusage & 0xFF;
  T[1] = (arcfourkeyusage >> 8) & 0xFF;
  T[2] = (arcfourkeyusage >> 16) & 0xFF;
  T[3] = (arcfourkeyusage >> 24) & 0xFF;

  memcpy (L40 + 10, T, 4);

  if (export)
    offset = 10;
  else
    offset = 0;

  err = shishi_hmac_md5 (handle,
			 shishi_key_value (key), shishi_key_length (key),
			 L40 + offset, 14 - offset, &K1);
  if (err)
    goto done;

  memcpy (K2, K1, 16);
  if (export)
    memset (K1 + 7, 0xAB, 9);

  pt = xmalloc (16 + 8 + inlen);

  memset (pt, 0, 16);
  err = shishi_randomize (handle, 0, pt + 16, 8);
  if (err)
    goto done;
  memcpy (pt + 16 + 8, in, inlen);

  err = shishi_hmac_md5 (handle, K2, 16, pt, 16 + 8 + inlen, &cksum);
  if (err)
    goto done;
  err = shishi_hmac_md5 (handle, K1, 16, cksum, 16, &K3);
  if (err)
    goto done;

  *outlen = 8 + inlen;
  err = shishi_arcfour (handle, 0, K3, 16, pt + 16, 8 + inlen, out);
  if (err)
    goto done;

  err = SHISHI_OK;

 done:
  free (cksum);
  free (K3);
  free (pt);
  free (K1);
  return err;
}

static int
arcfour_hmac_exp_encrypt (Shishi * handle,
		      Shishi_key * key,
		      int keyusage,
		      const char *iv,
		      size_t ivlen,
		      char **ivout, size_t * ivoutlen,
		      const char *in, size_t inlen,
		      char **out, size_t * outlen)
{
  return arcfour_hmac_encrypt (handle, key, keyusage, iv, ivlen,
			       ivout, ivoutlen, in, inlen, out, outlen);

}

static int
arcfour_hmac_exp_decrypt (Shishi * handle,
		      Shishi_key * key,
		      int keyusage,
		      const char *iv,
		      size_t ivlen,
		      char **ivout, size_t * ivoutlen,
		      const char *in, size_t inlen,
		      char **out, size_t * outlen)
{
  return arcfour_hmac_decrypt (handle, key, keyusage, iv, ivlen,
			       ivout, ivoutlen, in, inlen, out, outlen);
}

#define ARCFOUR_HMAC_CKSUM_KEY_DERIVE_CONSTANT "signaturekey"

static int
arcfour_hmac_md5_checksum (Shishi * handle,
		       Shishi_key * key,
		       int keyusage,
		       int cksumtype,
		       const char *in, size_t inlen,
		       char **out, size_t * outlen)
{
  int arcfourkeyusage = arcfour_keyusage (keyusage);
  char *Ksign = NULL;
  char *pt = NULL;
  char T[4];
  int err;

  T[0] = arcfourkeyusage & 0xFF;
  T[1] = (arcfourkeyusage >> 8) & 0xFF;
  T[2] = (arcfourkeyusage >> 16) & 0xFF;
  T[3] = (arcfourkeyusage >> 24) & 0xFF;

  err = shishi_hmac_md5 (handle,
			 shishi_key_value (key), shishi_key_length (key),
			 ARCFOUR_HMAC_CKSUM_KEY_DERIVE_CONSTANT,
			 strlen (ARCFOUR_HMAC_CKSUM_KEY_DERIVE_CONSTANT) + 1,
			 &Ksign);
  if (err)
    goto done;

  pt = xmalloc (4 + inlen);
  memcpy (pt, T, 4);
  memcpy (pt + 4, in, inlen);

  *outlen = 16;
  err = shishi_hmac_md5 (handle, Ksign, 16, in, inlen, out);
  if (err)
    goto done;

  err = SHISHI_OK;

 done:
  free (Ksign);
  free (pt);
  return err;
}

static int
arcfour_hmac_random_to_key (Shishi * handle,
			const char *random, size_t randomlen,
			Shishi_key * outkey)
{
  if (randomlen != shishi_key_length (outkey))
    {
      shishi_error_printf (handle, "ARCFOUR random to key caller error");
      return SHISHI_CRYPTO_ERROR;
    }

  shishi_key_value_set (outkey, random);

  return SHISHI_OK;
}

static int
arcfour_hmac_string_to_key (Shishi * handle,
			const char *string,
			size_t stringlen,
			const char *salt,
			size_t saltlen,
			const char *parameter, Shishi_key * outkey)
{
  char *tmp, *md;
  size_t tmplen, i;
  int rc;

  tmplen = 2 * stringlen;
  tmp = xmalloc (tmplen);

  for (i = 0; i < stringlen; i++)
    {
      tmp[2 * i] = string[i];
      tmp[2 * i + 1] = '\x0';
    }

  rc = shishi_md4 (handle, tmp, tmplen, &md);
  free (tmp);
  if (rc != SHISHI_OK)
    return rc;

  shishi_key_value_set (outkey, md);

  return SHISHI_OK;
}

cipherinfo arcfour_hmac_info = {
  SHISHI_ARCFOUR_HMAC,
  "arcfour-hmac",
  16,
  0,
  16,
  16,
  16,
  SHISHI_ARCFOUR_HMAC_MD5,
  arcfour_hmac_random_to_key,
  arcfour_hmac_string_to_key,
  arcfour_hmac_encrypt,
  arcfour_hmac_decrypt
};

cipherinfo arcfour_hmac_exp_info = {
  SHISHI_ARCFOUR_HMAC_EXP,
  "arcfour-hmac-exp",
  16,
  0,
  16,
  16,
  16,
  SHISHI_ARCFOUR_HMAC_MD5,
  arcfour_hmac_random_to_key,
  arcfour_hmac_string_to_key,
  arcfour_hmac_exp_encrypt,
  arcfour_hmac_exp_decrypt
};

checksuminfo arcfour_hmac_md5_info = {
  SHISHI_ARCFOUR_HMAC_MD5,
  "arcfour-hmac-md5",
  16,
  arcfour_hmac_md5_checksum
};
