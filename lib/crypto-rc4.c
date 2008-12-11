/* crypto-rc4.c --- draft-brezak-win2k-krb-rc4-hmac-04 crypto functions.
 * Copyright (C) 2003, 2004, 2006, 2007, 2008  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#include "internal.h"

/* Get prototypes. */
#include "crypto.h"

/* Get _shishi_escapeprint, etc. */
#include "utils.h"

static int
arcfour_keyusage (int keyusage)
{
  /* From draft-brezak-win2k-krb-rc4-hmac-04.txt:
   *
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
   */

  if (keyusage == SHISHI_KEYUSAGE_ENCASREPPART)
    return SHISHI_KEYUSAGE_ENCTGSREPPART_SESSION_KEY;
  else if (keyusage == SHISHI_KEYUSAGE_ENCTGSREPPART_AUTHENTICATOR_KEY)
    return SHISHI_KEYUSAGE_ENCTGSREPPART_SESSION_KEY;

  /* Continued, this probably refer to the non-standard 3DES GSSAPI
   * keyusages; RFC 1964 does not discuss key uses at all.  When this
   * comment was written, GSSLib did not support ARCFOUR though.
   *
   *    Relative to RFC-1964 key uses:
   *
   *    T = 0 in the generation of sequence number for the MIC token
   *    T = 0 in the generation of sequence number for the WRAP token
   *    T = 0 in the generation of encrypted data for the WRAPPED token
   *
   */

  if (keyusage == SHISHI_KEYUSAGE_GSS_R1 ||
      keyusage == SHISHI_KEYUSAGE_GSS_R2 ||
      keyusage == SHISHI_KEYUSAGE_GSS_R3)
    return 0;

  return keyusage;
}

static int
arcfour_hmac_encrypt (Shishi * handle,
		      Shishi_key * key,
		      int keyusage,
		      const char *iv,
		      size_t ivlen,
		      char **ivout, size_t * ivoutlen,
		      const char *in, size_t inlen, char **out,
		      size_t * outlen)
{
  int export = shishi_key_type (key) == SHISHI_ARCFOUR_HMAC_EXP;
  int arcfourkeyusage = arcfour_keyusage (keyusage);
  char L40[14] = "fortybits";
  uint8_t T[4];
  char *K1 = NULL;
  char K2[16];
  char *K3 = NULL;
  char *pt = NULL;
  size_t ptlen;
  char *ct = NULL;
  char *cksum = NULL;
  int offset;
  int err;

  T[0] = arcfourkeyusage & 0xFF;
  T[1] = (arcfourkeyusage >> 8) & 0xFF;
  T[2] = (arcfourkeyusage >> 16) & 0xFF;
  T[3] = (arcfourkeyusage >> 24) & 0xFF;

  memcpy (L40 + 10, T, 4);

  if (export)
    offset = 0;
  else
    offset = 10;

  if (VERBOSECRYPTONOISE (handle))
    {
      puts ("k1pt");
      _shishi_hexprint (L40 + offset, 14 - offset);
    }

  err = shishi_hmac_md5 (handle,
			 shishi_key_value (key), shishi_key_length (key),
			 L40 + offset, 14 - offset, &K1);
  if (err)
    goto done;

  if (VERBOSECRYPTONOISE (handle))
    {
      puts ("k1");
      _shishi_hexprint (K1, 16);
    }

  memcpy (K2, K1, 16);
  if (export)
    memset (K1 + 7, 0xAB, 9);

  if (VERBOSECRYPTONOISE (handle))
    {
      puts ("k1");
      _shishi_hexprint (K1, 16);
      puts ("k2");
      _shishi_hexprint (K2, 16);
    }

  /* Note that in ENCRYPT of draft-brezak-win2k-krb-rc4-hmac-04.txt change:
   *
   *     edata.Checksum = HMAC (K2, edata);
   *
   * into
   *
   *     edata.Checksum = HMAC (K2, concat(edata.Confounder, edata.Data));
   *
   * otherwise it will not work.  Compare DECRYPT where the later is
   * taken from.  Another interpretation would be to HMAC a zeroized
   * checksum field, like certain other cipher suites do, but that
   * does not interoperate.
   *
   */

  ptlen = 8 + inlen;
  pt = xmalloc (ptlen);

  err = shishi_randomize (handle, 0, pt, 8);
  if (err)
    goto done;
  memcpy (pt + 8, in, inlen);

  if (VERBOSECRYPTONOISE (handle))
    {
      puts ("random");
      _shishi_hexprint (pt, 8);
    }

  err = shishi_hmac_md5 (handle, K2, 16, pt, ptlen, &cksum);
  if (err)
    goto done;

  if (VERBOSECRYPTONOISE (handle))
    {
      puts ("cksum");
      _shishi_hexprint (cksum, 16);
    }

  err = shishi_hmac_md5 (handle, K1, 16, cksum, 16, &K3);
  if (err)
    goto done;

  if (VERBOSECRYPTONOISE (handle))
    {
      puts ("k3");
      _shishi_hexprint (K3, 16);
    }

  err = shishi_arcfour (handle, 0, K3, 16, iv, ivout, pt, ptlen, &ct);
  if (err)
    goto done;

  if (VERBOSECRYPTONOISE (handle))
    {
      puts ("ct");
      _shishi_hexprint (ct, ptlen);
    }

  *outlen = 16 + ptlen;
  *out = xmalloc (*outlen);
  memcpy (*out, cksum, 16);
  memcpy (*out + 16, ct, ptlen);

  if (ivoutlen)
    /* size = sbox[256] + int8_t i + int8_t j */
    *ivoutlen = 256 + 2 * 8;

  err = SHISHI_OK;

done:
  free (cksum);
  free (K3);
  free (pt);
  free (ct);
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
		      const char *in, size_t inlen, char **out,
		      size_t * outlen)
{
  int export = shishi_key_type (key) == SHISHI_ARCFOUR_HMAC_EXP;
  int arcfourkeyusage = arcfour_keyusage (keyusage);
  char L40[14] = "fortybits";
  uint8_t T[4];
  char *K1 = NULL;
  char K2[16];
  char *K3 = NULL;
  char *cksum = NULL;
  char *pt = NULL;
  int offset;
  int err;

  T[0] = arcfourkeyusage & 0xFF;
  T[1] = (arcfourkeyusage >> 8) & 0xFF;
  T[2] = (arcfourkeyusage >> 16) & 0xFF;
  T[3] = (arcfourkeyusage >> 24) & 0xFF;

  memcpy (L40 + 10, T, 4);

  if (export)
    offset = 0;
  else
    offset = 10;

  if (VERBOSECRYPTONOISE (handle))
    {
      puts ("k1pt");
      _shishi_hexprint (L40 + offset, 14 - offset);
    }

  err = shishi_hmac_md5 (handle,
			 shishi_key_value (key), shishi_key_length (key),
			 L40 + offset, 14 - offset, &K1);
  if (err)
    goto done;

  if (VERBOSECRYPTONOISE (handle))
    {
      puts ("k1");
      _shishi_hexprint (K1, 16);
    }

  memcpy (K2, K1, 16);
  if (export)
    memset (K1 + 7, 0xAB, 9);

  if (VERBOSECRYPTONOISE (handle))
    {
      puts ("k1");
      _shishi_hexprint (K1, 16);
      puts ("k2");
      _shishi_hexprint (K2, 16);
    }

  err = shishi_hmac_md5 (handle, K1, 16, in, 16, &K3);
  if (err)
    goto done;

  if (VERBOSECRYPTONOISE (handle))
    {
      puts ("k3");
      _shishi_hexprint (K3, 16);
    }

  err =
    shishi_arcfour (handle, 1, K3, 16, iv, ivout, in + 16, inlen - 16, &pt);
  if (err)
    goto done;

  if (VERBOSECRYPTONOISE (handle))
    {
      puts ("cksum pt");
      _shishi_hexprint (pt, inlen - 16);
    }

  err = shishi_hmac_md5 (handle, K2, 16, pt, inlen - 16, &cksum);
  if (err)
    goto done;

  if (VERBOSECRYPTONOISE (handle))
    {
      puts ("cksum");
      _shishi_hexprint (cksum, 16);
      puts ("cksumin");
      _shishi_hexprint (in, 16);
    }

  if (memcmp (cksum, in, 16) != 0)
    {
      err = SHISHI_CRYPTO_ERROR;
      goto done;
    }

  *outlen = inlen - 16 - 8;
  *out = xmalloc (*outlen);
  memcpy (*out, pt + 8, inlen - 16 - 8);

  if (ivoutlen)
    /* size = sbox[256] + int8_t i + int8_t j */
    *ivoutlen = 256 + 2 * 8;

  err = SHISHI_OK;

done:
  free (cksum);
  free (K3);
  free (K1);
  free (pt);
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
  size_t ptlen;
  char *tmp = NULL;
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

  if (VERBOSECRYPTONOISE (handle))
    {
      puts ("Ksign");
      _shishi_hexprint (Ksign, 16);
    }

  ptlen = 4 + inlen;
  pt = xmalloc (ptlen);
  memcpy (pt, T, 4);
  memcpy (pt + 4, in, inlen);

  if (VERBOSECRYPTONOISE (handle))
    {
      puts ("pt");
      _shishi_hexprint (pt, ptlen);
    }

  err = shishi_md5 (handle, pt, ptlen, &tmp);
  if (err)
    goto done;

  if (VERBOSECRYPTONOISE (handle))
    {
      puts ("md");
      _shishi_hexprint (tmp, 16);
    }

  *outlen = 16;
  err = shishi_hmac_md5 (handle, Ksign, 16, tmp, 16, out);
  if (err)
    goto done;

  if (VERBOSECRYPTONOISE (handle))
    {
      puts ("hmac");
      _shishi_hexprint (*out, 16);
    }

  err = SHISHI_OK;

done:
  free (Ksign);
  free (pt);
  free (tmp);
  return err;
}

static int
arcfour_hmac_random_to_key (Shishi * handle,
			    const char *rnd, size_t rndlen,
			    Shishi_key * outkey)
{
  if (rndlen != shishi_key_length (outkey))
    {
      shishi_error_printf (handle, "ARCFOUR random to key caller error");
      return SHISHI_CRYPTO_ERROR;
    }

  shishi_key_value_set (outkey, rnd);

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

  free (md);

  return SHISHI_OK;
}

cipherinfo arcfour_hmac_info = {
  SHISHI_ARCFOUR_HMAC,
  "arcfour-hmac",
  1,
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
  1,
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
  arcfour_hmac_md5_checksum,
  NULL
};
