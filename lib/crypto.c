/* crypto.c --- Crypto functions.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009  Simon Josefsson
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
rot13 (Shishi * handle, char *in, char *out, int len)
{
  if (VERBOSECRYPTONOISE (handle))
    {
      printf ("\t ;; rot 13 in:\n");
      _shishi_escapeprint (in, len);
      _shishi_hexprint (in, len);
      _shishi_binprint (in, len);
    }

  if (len == 1)
    {
      out[0] =
	((in[0] >> 5) & 0x01) |
	((in[0] >> 5) & 0x02) |
	((in[0] >> 5) & 0x04) |
	((in[0] << 3) & 0x08) |
	((in[0] << 3) & 0x10) |
	((in[0] << 3) & 0x20) | ((in[0] << 3) & 0x40) | ((in[0] << 3) & 0x80);
    }
  else if (len > 1)
    {
      char nexttolast, last;
      int i;

      nexttolast = in[len - 2];
      last = in[len - 1];

      for (i = len * 8 - 1; i >= 13; i--)
	{
	  int pos = i / 8;
	  char mask = ~(1 << (7 - i % 8));
	  int pos2 = (i - 13) / 8;
	  char mask2 = (1 << (7 - (i - 13) % 8));

	  out[pos] = (out[pos] & mask) |
	    (((in[pos2] & mask2) ? 0xFF : 0x00) & ~mask);
	}
      out[0] = ((nexttolast & 0xFF) << 3) | ((last & 0xFF) >> 5);
      out[1] = (in[1] & ~(0xFF & (0xFF << 3))) | (0xFF & (last << 3));
    }

  if (VERBOSECRYPTONOISE (handle))
    {
      printf ("\t ;; rot13 out:\n");
      _shishi_escapeprint (out, len);
      _shishi_hexprint (out, len);
      _shishi_binprint (out, len);
    }
}

static void
ocadd (char *add1, char *add2, char *sum, int len)
{
  int i;
  int carry = 0;

  for (i = len - 1; i >= 0; i--)
    {
      int tmpsum = (unsigned char) add1[i] + (unsigned char) add2[i];

      sum[i] = (tmpsum + carry) & 0xFF;
      if (tmpsum + carry > 0xFF)
	carry = 1;
      else
	carry = 0;
    }

  if (carry)
    {
      int done = 0;

      for (i = len - 1; i >= 0; i--)
	if ((unsigned char) sum[i] != 0xFF)
	  {
	    sum[i]++;
	    done = 1;
	    break;
	  }

      if (!done)
	memset (sum, 0, len);
    }
}

static int
simplified_hmac (Shishi * handle,
		 Shishi_key * key,
		 const char *in, size_t inlen,
		 char **outhash, size_t * outhashlen)
{
  *outhashlen = shishi_checksum_cksumlen
    (shishi_cipher_defaultcksumtype (shishi_key_type (key)));
  return shishi_hmac_sha1 (handle, shishi_key_value (key),
			   shishi_key_length (key), in, inlen, outhash);
}

static int
simplified_hmac_verify (Shishi * handle, Shishi_key * key,
			const char *in, size_t inlen,
			const char *hmac, size_t hmaclen)
{
  char *hash;
  size_t hlen;
  int same;
  int res;

  res = simplified_hmac (handle, key, in, inlen, &hash, &hlen);
  if (res != SHISHI_OK || hash == NULL)
    return res;

  if (VERBOSECRYPTO (handle))
    {
      printf ("\t ;; HMAC verify:\n");
      _shishi_escapeprint (hash, hlen);
      _shishi_hexprint (hash, hlen);
      _shishi_binprint (hash, hlen);
      _shishi_escapeprint (hmac, hmaclen);
      _shishi_hexprint (hmac, hmaclen);
      _shishi_binprint (hmac, hmaclen);
    }

  same = (hlen == hmaclen) && memcmp (hash, hmac, hmaclen) == 0;

  free (hash);

  if (!same)
    {
      shishi_error_printf (handle, "HMAC verify failed");
      return SHISHI_CRYPTO_ERROR;
    }

  return SHISHI_OK;
}

int
_shishi_simplified_derivekey (Shishi * handle,
			      Shishi_key * key,
			      int keyusage,
			      int derivekeymode, Shishi_key ** outkey)
{
  char prfconstant[5];
  int res = SHISHI_OK;
  Shishi_key *derivedkey;

  if (VERBOSECRYPTO (handle))
    {
      printf ("simplified_derivekey\n");
      printf ("\t ;; mode %d (%s)\n", derivekeymode,
	      derivekeymode == SHISHI_DERIVEKEYMODE_CHECKSUM ? "checksum" :
	      derivekeymode == SHISHI_DERIVEKEYMODE_INTEGRITY ? "integrity" :
	      derivekeymode == SHISHI_DERIVEKEYMODE_PRIVACY ? "privacy" :
	      "base-key");
      _shishi_hexprint (shishi_key_value (key), shishi_key_length (key));
    }


  res = shishi_key_from_value (handle, shishi_key_type (key),
			       NULL, &derivedkey);
  if (res != SHISHI_OK)
    return res;

  *outkey = derivedkey;

  if (keyusage)
    {
      uint32_t tmp = htonl (keyusage);
      memcpy (prfconstant, &tmp, 4);
      if (derivekeymode == SHISHI_DERIVEKEYMODE_CHECKSUM)
	prfconstant[4] = '\x99';
      else if (derivekeymode == SHISHI_DERIVEKEYMODE_INTEGRITY)
	prfconstant[4] = '\x55';
      else /* if (derivekeymode == SHISHI_DERIVEKEYMODE_PRIVACY) */
	prfconstant[4] = '\xAA';

      res = shishi_dk (handle, key, prfconstant, 5, derivedkey);
    }
  else
    {
      shishi_key_copy (derivedkey, key);
    }

  if (VERBOSECRYPTO (handle))
    {
      printf ("\t ;; simplified_derivekey out (%d):\n",
	      shishi_key_length (derivedkey));
      _shishi_hexprint (shishi_key_value (derivedkey),
			shishi_key_length (derivedkey));
    }

  return res;
}

int
_shishi_simplified_dencrypt (Shishi * handle,
			     Shishi_key * key,
			     const char *iv, size_t ivlen,
			     char **ivout, size_t * ivoutlen,
			     const char *in, size_t inlen,
			     char **out, size_t * outlen, int decryptp)
{
  int rc;
  char *pt;
  size_t ptlen;
  size_t padzerolen = 0;

  if ((inlen % 8) != 0)
    while (((inlen + padzerolen) % 8) != 0)
      padzerolen++;

  ptlen = inlen + padzerolen;

  if (padzerolen)
    {
      pt = xmalloc (ptlen);
      memcpy (pt, in, inlen);
      memset (pt + inlen, 0, padzerolen);
    }
  else
    pt = (char *) in;

  switch (shishi_key_type (key))
    {
    case SHISHI_DES_CBC_CRC:
    case SHISHI_DES_CBC_MD4:
    case SHISHI_DES_CBC_MD5:
    case SHISHI_DES_CBC_NONE:
      rc = shishi_des (handle, decryptp, shishi_key_value (key),
		       iv, ivout, pt, ptlen, out);
      if (ivoutlen)
	*ivoutlen = 8;
      if (outlen)
	*outlen = ptlen;
      break;

    case SHISHI_DES3_CBC_HMAC_SHA1_KD:
    case SHISHI_DES3_CBC_NONE:
      rc = shishi_3des (handle, decryptp, shishi_key_value (key),
			iv, ivout, pt, inlen + padzerolen, out);
      if (ivoutlen)
	*ivoutlen = 8;
      if (outlen)
	*outlen = ptlen;
      break;

    case SHISHI_AES128_CTS_HMAC_SHA1_96:
    case SHISHI_AES256_CTS_HMAC_SHA1_96:
      rc = shishi_aes_cts (handle, decryptp,
			   shishi_key_value (key), shishi_key_length (key),
			   iv, ivout, in, inlen, out);
      if (ivoutlen)
	*ivoutlen = 16;
      if (outlen)
	*outlen = inlen;
      break;

    default:
      rc = SHISHI_CRYPTO_ERROR;
    }

  if (padzerolen)
    free (pt);

  return rc;
}

int
_shishi_simplified_encrypt (Shishi * handle,
			    Shishi_key * key,
			    int keyusage,
			    const char *iv, size_t ivlen,
			    char **ivout, size_t * ivoutlen,
			    const char *in, size_t inlen,
			    char **out, size_t * outlen)
{
  int res;
  int padzerolen = 0;

  if ((shishi_key_type (key) == SHISHI_DES3_CBC_HMAC_SHA1_KD ||
       shishi_key_type (key) == SHISHI_DES_CBC_CRC ||
       shishi_key_type (key) == SHISHI_DES_CBC_MD4 ||
       shishi_key_type (key) == SHISHI_DES_CBC_MD5) && (inlen % 8) != 0)
    while (((inlen + padzerolen) % 8) != 0)
      padzerolen++;

  if (keyusage != 0)
    {
      char *pt = NULL, *ct = NULL, *hmac = NULL;
      int blen = shishi_cipher_blocksize (shishi_key_type (key));
      size_t ctlen, ptlen, hmaclen;
      Shishi_key *privacykey = NULL, *integritykey = NULL;

      ptlen = inlen + blen + padzerolen;
      pt = xmalloc (ptlen);

      res = shishi_randomize (handle, 0, pt, blen);
      if (res != SHISHI_OK)
	goto done;

      memcpy (pt + blen, in, inlen);
      memset (pt + blen + inlen, 0, padzerolen);

      res = _shishi_simplified_derivekey (handle, key, keyusage,
					  SHISHI_DERIVEKEYMODE_PRIVACY,
					  &privacykey);
      if (res != SHISHI_OK)
	goto done;

      res = _shishi_simplified_dencrypt (handle, privacykey,
					 iv, ivlen, ivout,
					 ivoutlen, pt, ptlen, &ct, &ctlen, 0);
      if (res != SHISHI_OK)
	goto done;


      res = _shishi_simplified_derivekey (handle, key, keyusage,
					  SHISHI_DERIVEKEYMODE_INTEGRITY,
					  &integritykey);
      if (res != SHISHI_OK)
	goto done;

      res = simplified_hmac (handle, integritykey, pt, ptlen,
			     &hmac, &hmaclen);
      if (res != SHISHI_OK)
	goto done;

      *outlen = ctlen + hmaclen;
      *out = xmalloc (*outlen);
      memcpy (*out, ct, ctlen);
      memcpy (*out + ctlen, hmac, hmaclen);

    done:
      if (privacykey)
	shishi_key_done (privacykey);
      if (integritykey)
	shishi_key_done (integritykey);
      if (hmac)
	free (hmac);
      if (ct)
	free (ct);
      if (pt)
	free (pt);
    }
  else
    {
      res = _shishi_simplified_dencrypt (handle, key, iv, ivlen,
					 ivout, ivoutlen,
					 in, inlen, out, outlen, 0);
    }

  return res;
}

int
_shishi_simplified_decrypt (Shishi * handle,
			    Shishi_key * key,
			    int keyusage,
			    const char *iv, size_t ivlen,
			    char **ivout, size_t * ivoutlen,
			    const char *in, size_t inlen,
			    char **out, size_t * outlen)
{
  int res;

  if (keyusage)
    {
      Shishi_key *privacykey = NULL, *integritykey = NULL;
      int blen = shishi_cipher_blocksize (shishi_key_type (key));
      size_t hlen = shishi_checksum_cksumlen
	(shishi_cipher_defaultcksumtype (shishi_key_type (key)));

      res = _shishi_simplified_derivekey (handle, key, keyusage,
					  SHISHI_DERIVEKEYMODE_PRIVACY,
					  &privacykey);
      if (res != SHISHI_OK)
	goto done;

      res = _shishi_simplified_dencrypt (handle, privacykey,
					 iv, ivlen, ivout, ivoutlen,
					 in, inlen - hlen, out, outlen, 1);
      if (res != SHISHI_OK)
	goto done;

      res = _shishi_simplified_derivekey (handle, key, keyusage,
					  SHISHI_DERIVEKEYMODE_INTEGRITY,
					  &integritykey);
      if (res != SHISHI_OK)
	goto done;

      res = simplified_hmac_verify (handle, integritykey, *out, *outlen,
				    in + inlen - hlen, hlen);

      if (res != SHISHI_OK)
	goto done;

      memmove (*out, *out + blen, *outlen - blen);
      *outlen = *outlen - blen;
      *out = xrealloc (*out, *outlen);

    done:
      if (privacykey)
	shishi_key_done (privacykey);
      if (integritykey)
	shishi_key_done (integritykey);
    }
  else
    {
      res = _shishi_simplified_dencrypt (handle, key, iv, ivlen,
					 ivout, ivoutlen,
					 in, inlen, out, outlen, 1);
    }

  return res;
}

int
_shishi_simplified_checksum (Shishi * handle,
			     Shishi_key * key,
			     int keyusage,
			     int cksumtype,
			     const char *in, size_t inlen,
			     char **out, size_t * outlen)
{
  Shishi_key *checksumkey;
  int cksumlen = shishi_checksum_cksumlen (cksumtype);
  int res;

  res = _shishi_simplified_derivekey (handle, key, keyusage,
				      SHISHI_DERIVEKEYMODE_CHECKSUM,
				      &checksumkey);
  if (res != SHISHI_OK)
    return res;

  res = simplified_hmac (handle, checksumkey, in, inlen, out, outlen);

  shishi_key_done (checksumkey);

  if (res != SHISHI_OK)
    return res;

  *outlen = cksumlen;

  return SHISHI_OK;
}

static cipherinfo *ciphers[] = {
#if WITH_NULL
  &null_info,
#endif
#if WITH_DES
  &des_cbc_crc_info,
  &des_cbc_md4_info,
  &des_cbc_md5_info,
  &des_cbc_none_info,
#endif
#if WITH_3DES
  &des3_cbc_none_info,
  &des3_cbc_sha1_kd_info,
#endif
#if WITH_AES
  &aes128_cts_hmac_sha1_96_info,
  &aes256_cts_hmac_sha1_96_info,
#endif
#if WITH_ARCFOUR
  &arcfour_hmac_info,
  &arcfour_hmac_exp_info
#endif
};

/**
 * shishi_cipher_supported_p:
 * @type: encryption type, see Shishi_etype.
 *
 * Find out if cipher is supported.
 *
 * Return value: Return 0 iff cipher is unsupported.
 **/
int
shishi_cipher_supported_p (int32_t type)
{
  size_t i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return 1;

  return 0;
}

/**
 * shishi_cipher_name:
 * @type: encryption type, see Shishi_etype.
 *
 * Read humanly readable string for cipher.
 *
 * Return value: Return name of encryption type,
 * e.g. "des3-cbc-sha1-kd", as defined in the standards.
 **/
const char *
shishi_cipher_name (int32_t type)
{
  size_t i;
  char *p;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    {
      if (type == ciphers[i]->type)
	return ciphers[i]->name;
    }

  asprintf (&p, "unknown cipher %d", type);
  return p;
}

/**
 * shishi_cipher_blocksize:
 * @type: encryption type, see Shishi_etype.
 *
 * Get block size for cipher.
 *
 * Return value: Return block size for encryption type, as defined in
 * the standards.
 **/
int
shishi_cipher_blocksize (int32_t type)
{
  size_t i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->blocksize;

  return -1;
}

/**
 * shishi_cipher_confoundersize:
 * @type: encryption type, see Shishi_etype.
 *
 * Get length of confounder for cipher.
 *
 * Return value: Returns the size of the confounder (random data) for
 * encryption type, as defined in the standards, or (size_t)-1 on
 * error (e.g., unsupported encryption type).
 **/
int
shishi_cipher_confoundersize (int32_t type)
{
  size_t i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->confoundersize;

  return -1;
}

/**
 * shishi_cipher_keylen:
 * @type: encryption type, see Shishi_etype.
 *
 * Get key length for cipher.
 *
 * Return value: Return length of key used for the encryption type, as
 * defined in the standards.
 **/
size_t
shishi_cipher_keylen (int32_t type)
{
  size_t i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->keylen;

  return -1;
}

/**
 * shishi_cipher_randomlen:
 * @type: encryption type, see Shishi_etype.
 *
 * Get length of random data for cipher.
 *
 * Return value: Return length of random used for the encryption type,
 * as defined in the standards, or (size_t)-1 on error (e.g.,
 * unsupported encryption type).
 **/
size_t
shishi_cipher_randomlen (int32_t type)
{
  size_t i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->randomlen;

  return -1;
}

/**
 * shishi_cipher_defaultcksumtype:
 * @type: encryption type, see Shishi_etype.
 *
 * Get the default checksum associated with cipher.
 *
 * Return value: Return associated checksum mechanism for the
 * encryption type, as defined in the standards.
 **/
int
shishi_cipher_defaultcksumtype (int32_t type)
{
  size_t i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->defaultcksumtype;

  return -1;
}

struct Cipher_aliases
{
  const char *name;
  int type;
};

static struct Cipher_aliases cipher_aliases[] = {
  {"des-crc", SHISHI_DES_CBC_CRC},
  {"des-md4", SHISHI_DES_CBC_MD4},
  {"des-md5", SHISHI_DES_CBC_MD5},
  {"des", SHISHI_DES_CBC_MD5},
  {"des3", SHISHI_DES3_CBC_HMAC_SHA1_KD},
  {"3des", SHISHI_DES3_CBC_HMAC_SHA1_KD},
  {"aes128", SHISHI_AES128_CTS_HMAC_SHA1_96},
  {"aes256", SHISHI_AES256_CTS_HMAC_SHA1_96},
  {"aes", SHISHI_AES256_CTS_HMAC_SHA1_96},
  {"arcfour", SHISHI_ARCFOUR_HMAC}
};

/**
 * shishi_cipher_parse:
 * @cipher: name of encryption type, e.g. "des3-cbc-sha1-kd".
 *
 * Get cipher number by parsing string.
 *
 * Return value: Return encryption type corresponding to a string.
 **/
int
shishi_cipher_parse (const char *cipher)
{
  size_t i;
  char *endptr;

  i = strtol (cipher, &endptr, 0);

  if (endptr != cipher)
    return i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (strcasecmp (cipher, ciphers[i]->name) == 0)
      return ciphers[i]->type;

  for (i = 0; i < sizeof (cipher_aliases) / sizeof (cipher_aliases[0]); i++)
    if (strcasecmp (cipher, cipher_aliases[i].name) == 0)
      return cipher_aliases[i].type;

  return -1;
}

static Shishi_random_to_key_function
_shishi_cipher_random_to_key (int32_t type)
{
  size_t i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->random2key;

  return NULL;
}

static Shishi_string_to_key_function
_shishi_cipher_string_to_key (int32_t type)
{
  size_t i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->string2key;

  return NULL;
}

static Shishi_encrypt_function
_shishi_cipher_encrypt (int32_t type)
{
  size_t i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->encrypt;

  return NULL;
}

static Shishi_decrypt_function
_shishi_cipher_decrypt (int32_t type)
{
  size_t i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->decrypt;

  return NULL;
}

static checksuminfo *checksums[] = {
#if WITH_DES
  &crc32_info,
#endif
#if WITH_MD
  &md4_info,
#endif
#if WITH_DES
  &md4_des_info,
#endif
#if WITH_MD
  &md5_info,
#endif
#if WITH_DES
  &md5_des_info,
  &md5_gss_info,
#endif
#if WITH_3DES
  &hmac_sha1_des3_kd_info,
#endif
#if WITH_AES
  &hmac_sha1_96_aes128_info,
  &hmac_sha1_96_aes256_info,
#endif
#if WITH_ARCFOUR
  &arcfour_hmac_md5_info
#endif
};

/**
 * shishi_checksum_supported_p:
 * @type: checksum type, see Shishi_cksumtype.
 *
 * Find out whether checksum is supported.
 *
 * Return value: Return 0 iff checksum is unsupported.
 **/
int
shishi_checksum_supported_p (int32_t type)
{
  size_t i;

  for (i = 0; i < sizeof (checksums) / sizeof (checksums[0]); i++)
    if (type == checksums[i]->type)
      return 1;

  return 0;
}

/**
 * shishi_checksum_name:
 * @type: checksum type, see Shishi_cksumtype.
 *
 * Get name of checksum.
 *
 * Return value: Return name of checksum type,
 * e.g. "hmac-sha1-96-aes256", as defined in the standards.
 **/
const char *
shishi_checksum_name (int32_t type)
{
  size_t i;
  char *p;

  for (i = 0; i < sizeof (checksums) / sizeof (checksums[0]); i++)
    {
      if (type == checksums[i]->type)
	return checksums[i]->name;
    }

  asprintf (&p, "unknown checksum %d", type);
  return p;
}

/**
 * shishi_checksum_cksumlen:
 * @type: checksum type, see Shishi_cksumtype.
 *
 * Get length of checksum output.
 *
 * Return value: Return length of checksum used for the checksum type,
 * as defined in the standards.
 **/
size_t
shishi_checksum_cksumlen (int32_t type)
{
  size_t i;

  for (i = 0; i < sizeof (checksums) / sizeof (checksums[0]); i++)
    if (type == checksums[i]->type)
      return checksums[i]->cksumlen;

  return -1;
}

/**
 * shishi_checksum_parse:
 * @checksum: name of checksum type, e.g. "hmac-sha1-96-aes256".
 *
 * Get checksum number by parsing a string.
 *
 * Return value: Return checksum type, see Shishi_cksumtype,
 * corresponding to a string.
 **/
int
shishi_checksum_parse (const char *checksum)
{
  size_t i;
  char *endptr;

  i = strtol (checksum, &endptr, 0);

  if (endptr != checksum)
    return i;

  for (i = 0; i < sizeof (checksums) / sizeof (checksums[0]); i++)
    if (strcasecmp (checksum, checksums[i]->name) == 0)
      return checksums[i]->type;

  return -1;
}

static Shishi_checksum_function
_shishi_checksum (int32_t type)
{
  size_t i;

  for (i = 0; i < sizeof (checksums) / sizeof (checksums[0]); i++)
    if (type == checksums[i]->type)
      return checksums[i]->checksum;

  return NULL;
}

static Shishi_verify_function
_shishi_verify (int32_t type)
{
  size_t i;

  for (i = 0; i < sizeof (checksums) / sizeof (checksums[0]); i++)
    if (type == checksums[i]->type)
      return checksums[i]->verify;

  return NULL;
}

/**
 * shishi_string_to_key:
 * @handle: shishi handle as allocated by shishi_init().
 * @keytype: cryptographic encryption type, see Shishi_etype.
 * @password: input array with password.
 * @passwordlen: length of input array with password.
 * @salt: input array with salt.
 * @saltlen: length of input array with salt.
 * @parameter: input array with opaque encryption type specific information.
 * @outkey: allocated key handle that will contain new key.
 *
 * Derive key from a string (password) and salt (commonly
 * concatenation of realm and principal) for specified key type, and
 * set the type and value in the given key to the computed values.
 * The parameter value is specific for each keytype, and can be set if
 * the parameter information is not available.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_string_to_key (Shishi * handle,
		      int32_t keytype,
		      const char *password, size_t passwordlen,
		      const char *salt, size_t saltlen,
		      const char *parameter, Shishi_key * outkey)
{
  Shishi_string_to_key_function string2key;
  int res;

  shishi_key_type_set (outkey, keytype);

  if (VERBOSECRYPTO (handle))
    {
      printf ("string_to_key (%s, password, salt)\n",
	      shishi_key_name (outkey));
      printf ("\t ;; password:\n");
      _shishi_escapeprint (password, passwordlen);
      _shishi_hexprint (password, passwordlen);
      printf ("\t ;; salt:\n");
      _shishi_escapeprint (salt, saltlen);
      _shishi_hexprint (salt, saltlen);
    }

  string2key = _shishi_cipher_string_to_key (shishi_key_type (outkey));
  if (string2key == NULL)
    {
      shishi_error_printf (handle, "Unsupported keytype %d",
			   shishi_key_type (outkey));
      return SHISHI_CRYPTO_ERROR;
    }

  res = (*string2key) (handle, password, passwordlen,
		       salt, saltlen, parameter, outkey);

  if (VERBOSECRYPTO (handle))
    {
      printf ("\t ;; string_to_key key:\n");
      _shishi_hexprint (shishi_key_value (outkey),
			shishi_key_length (outkey));
      _shishi_binprint (shishi_key_value (outkey),
			shishi_key_length (outkey));
    }

  return res;
}

/**
 * shishi_random_to_key:
 * @handle: shishi handle as allocated by shishi_init().
 * @keytype: cryptographic encryption type, see Shishi_etype.
 * @rnd: input array with random data.
 * @rndlen: length of input array with random data.
 * @outkey: allocated key handle that will contain new key.
 *
 * Derive key from random data for specified key type, and set the
 * type and value in the given key to the computed values.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_random_to_key (Shishi * handle,
		      int32_t keytype,
		      const char *rnd, size_t rndlen, Shishi_key * outkey)
{
  Shishi_random_to_key_function random2key;
  int res;

  shishi_key_type_set (outkey, keytype);

  if (VERBOSECRYPTO (handle))
    {
      printf ("random_to_key (%s, random)\n", shishi_key_name (outkey));
      printf ("\t ;; random:\n");
      _shishi_hexprint (rnd, rndlen);
      _shishi_binprint (rnd, rndlen);
    }

  random2key = _shishi_cipher_random_to_key (keytype);
  if (random2key == NULL)
    {
      shishi_error_printf (handle, "Unsupported random_to_key() ekeytype %d",
			   keytype);
      return SHISHI_CRYPTO_ERROR;
    }

  res = (*random2key) (handle, rnd, rndlen, outkey);

  if (VERBOSECRYPTO (handle))
    {
      printf ("\t ;; random_to_key key:\n");
      _shishi_hexprint (shishi_key_value (outkey),
			shishi_key_length (outkey));
      _shishi_binprint (shishi_key_value (outkey),
			shishi_key_length (outkey));
    }

  return res;
}

/**
 * shishi_checksum:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to compute checksum with.
 * @keyusage: integer specifying what this key is used for.
 * @cksumtype: the checksum algorithm to use.
 * @in: input array with data to integrity protect.
 * @inlen: size of input array with data to integrity protect.
 * @out: output array with newly allocated integrity protected data.
 * @outlen: output variable with length of output array with checksum.
 *
 * Integrity protect data using key, possibly altered by supplied key
 * usage.  If key usage is 0, no key derivation is used.  The OUT
 * buffer must be deallocated by the caller.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_checksum (Shishi * handle,
		 Shishi_key * key,
		 int keyusage,
		 int cksumtype,
		 const char *in, size_t inlen, char **out, size_t * outlen)
{
  Shishi_checksum_function checksum;
  int res;

  if (VERBOSECRYPTO (handle))
    {
      printf ("checksum (%s, %d, in, out)\n",
	      shishi_key_name (key), cksumtype);
      printf ("\t ;; key (%d):\n", shishi_key_length (key));
      _shishi_hexprint (shishi_key_value (key), shishi_key_length (key));
      printf ("\t ;; in:\n");
      _shishi_escapeprint (in, inlen);
      _shishi_hexprint (in, inlen);
    }

  if (cksumtype == 0)
    cksumtype = shishi_cipher_defaultcksumtype (shishi_key_type (key));

  checksum = _shishi_checksum (cksumtype);
  if (checksum == NULL)
    {
      shishi_error_printf (handle, "Unsupported checksum type %d", cksumtype);
      return SHISHI_CRYPTO_ERROR;
    }

  /* XXX? check if etype and cksumtype are compatible? */

  res = (*checksum) (handle, key, keyusage, cksumtype,
		     in, inlen, out, outlen);

  if (VERBOSECRYPTO (handle))
    {
      printf ("\t ;; checksum out:\n");
      _shishi_escapeprint (*out, *outlen);
      _shishi_hexprint (*out, *outlen);
    }

  return res;
}

/**
 * shishi_verify:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to verify checksum with.
 * @keyusage: integer specifying what this key is used for.
 * @cksumtype: the checksum algorithm to use.
 * @in: input array with data that was integrity protected.
 * @inlen: size of input array with data that was integrity protected.
 * @cksum: input array with alleged checksum of data.
 * @cksumlen: size of input array with alleged checksum of data.
 *
 * Verify checksum of data using key, possibly altered by supplied key
 * usage.  If key usage is 0, no key derivation is used.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_verify (Shishi * handle,
	       Shishi_key * key,
	       int keyusage,
	       int cksumtype,
	       const char *in, size_t inlen,
	       const char *cksum, size_t cksumlen)
{
  Shishi_verify_function verify;
  int res;

  if (VERBOSECRYPTO (handle))
    {
      printf ("verify (%s, %d, in, out)\n", shishi_key_name (key), cksumtype);
      printf ("\t ;; key (%d):\n", shishi_key_length (key));
      _shishi_hexprint (shishi_key_value (key), shishi_key_length (key));
      printf ("\t ;; data:\n");
      _shishi_escapeprint (in, inlen);
      _shishi_hexprint (in, inlen);
      printf ("\t ;; mic:\n");
      _shishi_escapeprint (cksum, cksumlen);
      _shishi_hexprint (cksum, cksumlen);
    }

  if (cksumtype == 0)
    cksumtype = shishi_cipher_defaultcksumtype (shishi_key_type (key));

  verify = _shishi_verify (cksumtype);
  if (verify == NULL)
    {
      shishi_error_printf (handle, "Unsupported checksum type %d", cksumtype);
      return SHISHI_CRYPTO_ERROR;
    }

  /* XXX? check if etype and cksumtype are compatible? */

  res = (*verify) (handle, key, keyusage, cksumtype,
		   in, inlen, cksum, cksumlen);

  if (VERBOSECRYPTO (handle))
    printf ("\t ;; verify return: %d\n", res);

  return res;
}

/**
 * shishi_encrypt_ivupdate_etype:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to encrypt with.
 * @keyusage: integer specifying what this key is encrypting.
 * @etype: integer specifying what cipher to use.
 * @iv: input array with initialization vector
 * @ivlen: size of input array with initialization vector.
 * @ivout: output array with newly allocated updated initialization vector.
 * @ivoutlen: size of output array with updated initialization vector.
 * @in: input array with data to encrypt.
 * @inlen: size of input array with data to encrypt.
 * @out: output array with newly allocated encrypted data.
 * @outlen: output variable with size of newly allocated output array.
 *
 * Encrypts data as per encryption method using specified
 * initialization vector and key.  The key actually used is derived
 * using the key usage.  If key usage is 0, no key derivation is used.
 * The OUT buffer must be deallocated by the caller.  If IVOUT or
 * IVOUTLEN is NULL, the updated IV is not saved anywhere.
 *
 * Note that DECRYPT(ENCRYPT(data)) does not necessarily yield data
 * exactly.  Some encryption types add pad to make the data fit into
 * the block size of the encryption algorithm.  Furthermore, the pad
 * is not guaranteed to look in any special way, although existing
 * implementations often pad with the zero byte.  This means that you
 * may have to "frame" data, so it is possible to infer the original
 * length after decryption.  Compare ASN.1 DER which contains such
 * information.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_encrypt_ivupdate_etype (Shishi * handle,
			       Shishi_key * key,
			       int keyusage,
			       int32_t etype,
			       const char *iv, size_t ivlen,
			       char **ivout, size_t * ivoutlen,
			       const char *in, size_t inlen,
			       char **out, size_t * outlen)
{
  Shishi_encrypt_function enc;
  int res;

  if (VERBOSECRYPTO (handle))
    {
      printf ("encrypt (type=%s, usage=%d, key, in)\n",
	      shishi_key_name (key), keyusage);
      printf ("\t ;; key (%d):\n", shishi_key_length (key));
      _shishi_hexprint (shishi_key_value (key), shishi_key_length (key));
      printf ("\t ;; in (%d):\n", inlen);
      _shishi_escapeprint (in, inlen);
      _shishi_hexprint (in, inlen);
      if (iv)
	{
	  printf ("\t ;; iv (%d):\n", ivlen);
	  _shishi_escapeprint (iv, ivlen);
	  _shishi_hexprint (iv, ivlen);
	}
    }

  enc = _shishi_cipher_encrypt (etype);
  if (enc == NULL)
    {
      shishi_error_printf (handle, "Unsupported keytype %d",
			   shishi_key_type (key));
      return SHISHI_CRYPTO_ERROR;
    }

  res = (*enc) (handle, key, keyusage, iv, ivlen, ivout, ivoutlen,
		in, inlen, out, outlen);

  if (VERBOSECRYPTO (handle))
    {
      if (res == SHISHI_OK)
	{
	  printf ("\t ;; encrypt out:\n");
	  _shishi_escapeprint (*out, *outlen);
	  _shishi_hexprint (*out, *outlen);
	  if (ivout && ivoutlen)
	    {
	      printf ("\t ;; iv out:\n");
	      _shishi_escapeprint (*ivout, *ivoutlen);
	      _shishi_hexprint (*ivout, *ivoutlen);
	    }
	}
      else
	{
	  printf ("\t ;; encrypt out failed %d\n", res);
	}
    }

  return res;
}

/**
 * shishi_encrypt_iv_etype:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to encrypt with.
 * @keyusage: integer specifying what this key is encrypting.
 * @etype: integer specifying what cipher to use.
 * @iv: input array with initialization vector
 * @ivlen: size of input array with initialization vector.
 * @in: input array with data to encrypt.
 * @inlen: size of input array with data to encrypt.
 * @out: output array with newly allocated encrypted data.
 * @outlen: output variable with size of newly allocated output array.
 *
 * Encrypts data as per encryption method using specified
 * initialization vector and key.  The key actually used is derived
 * using the key usage.  If key usage is 0, no key derivation is used.
 * The OUT buffer must be deallocated by the caller.  The next IV is
 * lost, see shishi_encrypt_ivupdate_etype if you need it.
 *
 * Note that DECRYPT(ENCRYPT(data)) does not necessarily yield data
 * exactly.  Some encryption types add pad to make the data fit into
 * the block size of the encryption algorithm.  Furthermore, the pad
 * is not guaranteed to look in any special way, although existing
 * implementations often pad with the zero byte.  This means that you
 * may have to "frame" data, so it is possible to infer the original
 * length after decryption.  Compare ASN.1 DER which contains such
 * information.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_encrypt_iv_etype (Shishi * handle,
			 Shishi_key * key,
			 int keyusage,
			 int32_t etype,
			 const char *iv, size_t ivlen,
			 const char *in, size_t inlen,
			 char **out, size_t * outlen)
{
  return shishi_encrypt_ivupdate_etype (handle, key, keyusage, etype,
					iv, ivlen, NULL, NULL,
					in, inlen, out, outlen);
}

/**
 * shishi_encrypt_etype:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to encrypt with.
 * @keyusage: integer specifying what this key is encrypting.
 * @etype: integer specifying what cipher to use.
 * @in: input array with data to encrypt.
 * @inlen: size of input array with data to encrypt.
 * @out: output array with newly allocated encrypted data.
 * @outlen: output variable with size of newly allocated output array.
 *
 * Encrypts data as per encryption method using specified
 * initialization vector and key.  The key actually used is derived
 * using the key usage.  If key usage is 0, no key derivation is used.
 * The OUT buffer must be deallocated by the caller.  The default IV
 * is used, see shishi_encrypt_iv_etype if you need to alter it. The
 * next IV is lost, see shishi_encrypt_ivupdate_etype if you need it.
 *
 * Note that DECRYPT(ENCRYPT(data)) does not necessarily yield data
 * exactly.  Some encryption types add pad to make the data fit into
 * the block size of the encryption algorithm.  Furthermore, the pad
 * is not guaranteed to look in any special way, although existing
 * implementations often pad with the zero byte.  This means that you
 * may have to "frame" data, so it is possible to infer the original
 * length after decryption.  Compare ASN.1 DER which contains such
 * information.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_encrypt_etype (Shishi * handle,
		      Shishi_key * key,
		      int keyusage,
		      int32_t etype,
		      const char *in, size_t inlen,
		      char **out, size_t * outlen)
{
  return shishi_encrypt_ivupdate_etype (handle, key, keyusage,
					shishi_key_type (key),
					NULL, 0, NULL, NULL,
					in, inlen, out, outlen);
}

/**
 * shishi_encrypt_ivupdate:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to encrypt with.
 * @keyusage: integer specifying what this key is encrypting.
 * @iv: input array with initialization vector
 * @ivlen: size of input array with initialization vector.
 * @ivout: output array with newly allocated updated initialization vector.
 * @ivoutlen: size of output array with updated initialization vector.
 * @in: input array with data to encrypt.
 * @inlen: size of input array with data to encrypt.
 * @out: output array with newly allocated encrypted data.
 * @outlen: output variable with size of newly allocated output array.
 *
 * Encrypts data using specified initialization vector and key.  The
 * key actually used is derived using the key usage.  If key usage is
 * 0, no key derivation is used.  The OUT buffer must be deallocated
 * by the caller.  If IVOUT or IVOUTLEN is NULL, the updated IV is not
 * saved anywhere.
 *
 * Note that DECRYPT(ENCRYPT(data)) does not necessarily yield data
 * exactly.  Some encryption types add pad to make the data fit into
 * the block size of the encryption algorithm.  Furthermore, the pad
 * is not guaranteed to look in any special way, although existing
 * implementations often pad with the zero byte.  This means that you
 * may have to "frame" data, so it is possible to infer the original
 * length after decryption.  Compare ASN.1 DER which contains such
 * information.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_encrypt_ivupdate (Shishi * handle,
			 Shishi_key * key,
			 int keyusage,
			 const char *iv, size_t ivlen,
			 char **ivout, size_t * ivoutlen,
			 const char *in, size_t inlen,
			 char **out, size_t * outlen)
{
  return shishi_encrypt_ivupdate_etype (handle, key, keyusage,
					shishi_key_type (key),
					iv, ivlen, ivout, ivoutlen,
					in, inlen, out, outlen);
}

/**
 * shishi_encrypt_iv:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to encrypt with.
 * @keyusage: integer specifying what this key is encrypting.
 * @iv: input array with initialization vector
 * @ivlen: size of input array with initialization vector.
 * @in: input array with data to encrypt.
 * @inlen: size of input array with data to encrypt.
 * @out: output array with newly allocated encrypted data.
 * @outlen: output variable with size of newly allocated output array.
 *
 * Encrypts data using specified initialization vector and key.  The
 * key actually used is derived using the key usage.  If key usage is
 * 0, no key derivation is used.  The OUT buffer must be deallocated
 * by the caller.  The next IV is lost, see shishi_encrypt_ivupdate if
 * you need it.
 *
 * Note that DECRYPT(ENCRYPT(data)) does not necessarily yield data
 * exactly.  Some encryption types add pad to make the data fit into
 * the block size of the encryption algorithm.  Furthermore, the pad
 * is not guaranteed to look in any special way, although existing
 * implementations often pad with the zero byte.  This means that you
 * may have to "frame" data, so it is possible to infer the original
 * length after decryption.  Compare ASN.1 DER which contains such
 * information.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_encrypt_iv (Shishi * handle,
		   Shishi_key * key,
		   int keyusage,
		   const char *iv, size_t ivlen,
		   const char *in, size_t inlen, char **out, size_t * outlen)
{
  return shishi_encrypt_ivupdate_etype (handle, key, keyusage,
					shishi_key_type (key),
					iv, ivlen, NULL, NULL,
					in, inlen, out, outlen);
}

/**
 * shishi_encrypt:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to encrypt with.
 * @keyusage: integer specifying what this key is encrypting.
 * @in: input array with data to encrypt.
 * @inlen: size of input array with data to encrypt.
 * @out: output array with newly allocated encrypted data.
 * @outlen: output variable with size of newly allocated output array.
 *
 * Encrypts data using specified key.  The key actually used is
 * derived using the key usage.  If key usage is 0, no key derivation
 * is used.  The OUT buffer must be deallocated by the caller.  The
 * default IV is used, see shishi_encrypt_iv if you need to alter it.
 * The next IV is lost, see shishi_encrypt_ivupdate if you need it.
 *
 * Note that DECRYPT(ENCRYPT(data)) does not necessarily yield data
 * exactly.  Some encryption types add pad to make the data fit into
 * the block size of the encryption algorithm.  Furthermore, the pad
 * is not guaranteed to look in any special way, although existing
 * implementations often pad with the zero byte.  This means that you
 * may have to "frame" data, so it is possible to infer the original
 * length after decryption.  Compare ASN.1 DER which contains such
 * information.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_encrypt (Shishi * handle,
		Shishi_key * key,
		int keyusage,
		char *in, size_t inlen, char **out, size_t * outlen)
{
  return shishi_encrypt_ivupdate_etype (handle, key, keyusage,
					shishi_key_type (key),
					NULL, 0, NULL, NULL,
					in, inlen, out, outlen);
}

/**
 * shishi_decrypt_ivupdate_etype:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to decrypt with.
 * @keyusage: integer specifying what this key is decrypting.
 * @etype: integer specifying what cipher to use.
 * @iv: input array with initialization vector
 * @ivlen: size of input array with initialization vector.
 * @ivout: output array with newly allocated updated initialization vector.
 * @ivoutlen: size of output array with updated initialization vector.
 * @in: input array with data to decrypt.
 * @inlen: size of input array with data to decrypt.
 * @out: output array with newly allocated decrypted data.
 * @outlen: output variable with size of newly allocated output array.
 *
 * Decrypts data as per encryption method using specified
 * initialization vector and key.  The key actually used is derived
 * using the key usage.  If key usage is 0, no key derivation is used.
 * The OUT buffer must be deallocated by the caller.  If IVOUT or
 * IVOUTLEN is NULL, the updated IV is not saved anywhere.
 *
 * Note that DECRYPT(ENCRYPT(data)) does not necessarily yield data
 * exactly.  Some encryption types add pad to make the data fit into
 * the block size of the encryption algorithm.  Furthermore, the pad
 * is not guaranteed to look in any special way, although existing
 * implementations often pad with the zero byte.  This means that you
 * may have to "frame" data, so it is possible to infer the original
 * length after decryption.  Compare ASN.1 DER which contains such
 * information.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_decrypt_ivupdate_etype (Shishi * handle,
			       Shishi_key * key,
			       int keyusage,
			       int32_t etype,
			       const char *iv, size_t ivlen,
			       char **ivout, size_t * ivoutlen,
			       const char *in, size_t inlen,
			       char **out, size_t * outlen)
{
  Shishi_decrypt_function decrypt;
  int res;

  if (VERBOSECRYPTO (handle))
    {
      printf ("decrypt (type=%s, usage=%d, key, in, out)\n",
	      shishi_key_name (key), keyusage);
      printf ("\t ;; key (%d):\n", shishi_key_length (key));
      _shishi_hexprint (shishi_key_value (key), shishi_key_length (key));
      printf ("\t ;; in (%d):\n", inlen);
      _shishi_escapeprint (in, inlen);
      _shishi_hexprint (in, inlen);
      if (iv)
	{
	  printf ("\t ;; iv (%d):\n", ivlen);
	  _shishi_escapeprint (iv, ivlen);
	  _shishi_hexprint (iv, ivlen);
	}
    }

  decrypt = _shishi_cipher_decrypt (etype);
  if (decrypt == NULL)
    {
      shishi_error_printf (handle, "Unsupported keytype %d",
			   shishi_key_type (key));
      return SHISHI_CRYPTO_ERROR;
    }

  res = (*decrypt) (handle, key, keyusage,
		    iv, ivlen, ivout, ivoutlen, in, inlen, out, outlen);

  if (VERBOSECRYPTO (handle))
    {
      if (res == SHISHI_OK)
	{
	  printf ("\t ;; decrypt out:\n");
	  _shishi_escapeprint (*out, *outlen);
	  _shishi_hexprint (*out, *outlen);
	}
      else
	{
	  printf ("\t ;; decrypt out failed %d\n", res);
	}
    }

  return res;
}

/**
 * shishi_decrypt_iv_etype:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to decrypt with.
 * @keyusage: integer specifying what this key is decrypting.
 * @etype: integer specifying what cipher to use.
 * @iv: input array with initialization vector
 * @ivlen: size of input array with initialization vector.
 * @in: input array with data to decrypt.
 * @inlen: size of input array with data to decrypt.
 * @out: output array with newly allocated decrypted data.
 * @outlen: output variable with size of newly allocated output array.
 *
 * Decrypts data as per encryption method using specified
 * initialization vector and key.  The key actually used is derived
 * using the key usage.  If key usage is 0, no key derivation is used.
 * The OUT buffer must be deallocated by the caller.  The next IV is
 * lost, see shishi_decrypt_ivupdate_etype if you need it.
 *
 * Note that DECRYPT(ENCRYPT(data)) does not necessarily yield data
 * exactly.  Some encryption types add pad to make the data fit into
 * the block size of the encryption algorithm.  Furthermore, the pad
 * is not guaranteed to look in any special way, although existing
 * implementations often pad with the zero byte.  This means that you
 * may have to "frame" data, so it is possible to infer the original
 * length after decryption.  Compare ASN.1 DER which contains such
 * information.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_decrypt_iv_etype (Shishi * handle,
			 Shishi_key * key,
			 int keyusage,
			 int32_t etype,
			 const char *iv, size_t ivlen,
			 const char *in, size_t inlen,
			 char **out, size_t * outlen)
{
  return shishi_decrypt_ivupdate_etype (handle, key, keyusage, etype,
					iv, ivlen, NULL, NULL,
					in, inlen, out, outlen);
}

/**
 * shishi_decrypt_etype:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to decrypt with.
 * @keyusage: integer specifying what this key is decrypting.
 * @etype: integer specifying what cipher to use.
 * @in: input array with data to decrypt.
 * @inlen: size of input array with data to decrypt.
 * @out: output array with newly allocated decrypted data.
 * @outlen: output variable with size of newly allocated output array.
 *
 * Decrypts data as per encryption method using specified key.  The
 * key actually used is derived using the key usage.  If key usage is
 * 0, no key derivation is used.  The OUT buffer must be deallocated
 * by the caller.  The default IV is used, see shishi_decrypt_iv_etype
 * if you need to alter it.  The next IV is lost, see
 * shishi_decrypt_ivupdate_etype if you need it.
 *
 * Note that DECRYPT(ENCRYPT(data)) does not necessarily yield data
 * exactly.  Some encryption types add pad to make the data fit into
 * the block size of the encryption algorithm.  Furthermore, the pad
 * is not guaranteed to look in any special way, although existing
 * implementations often pad with the zero byte.  This means that you
 * may have to "frame" data, so it is possible to infer the original
 * length after decryption.  Compare ASN.1 DER which contains such
 * information.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_decrypt_etype (Shishi * handle,
		      Shishi_key * key,
		      int keyusage,
		      int32_t etype,
		      const char *in, size_t inlen,
		      char **out, size_t * outlen)
{
  return shishi_decrypt_ivupdate_etype (handle, key, keyusage, etype,
					NULL, 0, NULL, NULL,
					in, inlen, out, outlen);
}

/**
 * shishi_decrypt_ivupdate:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to decrypt with.
 * @keyusage: integer specifying what this key is decrypting.
 * @iv: input array with initialization vector
 * @ivlen: size of input array with initialization vector.
 * @ivout: output array with newly allocated updated initialization vector.
 * @ivoutlen: size of output array with updated initialization vector.
 * @in: input array with data to decrypt.
 * @inlen: size of input array with data to decrypt.
 * @out: output array with newly allocated decrypted data.
 * @outlen: output variable with size of newly allocated output array.
 *
 * Decrypts data using specified initialization vector and key.  The
 * key actually used is derived using the key usage.  If key usage is
 * 0, no key derivation is used.  The OUT buffer must be deallocated
 * by the caller.  If IVOUT or IVOUTLEN is NULL, the updated IV is not
 * saved anywhere.
 *
 * Note that DECRYPT(ENCRYPT(data)) does not necessarily yield data
 * exactly.  Some encryption types add pad to make the data fit into
 * the block size of the encryption algorithm.  Furthermore, the pad
 * is not guaranteed to look in any special way, although existing
 * implementations often pad with the zero byte.  This means that you
 * may have to "frame" data, so it is possible to infer the original
 * length after decryption.  Compare ASN.1 DER which contains such
 * information.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_decrypt_ivupdate (Shishi * handle,
			 Shishi_key * key,
			 int keyusage,
			 const char *iv, size_t ivlen,
			 char **ivout, size_t * ivoutlen,
			 const char *in, size_t inlen,
			 char **out, size_t * outlen)
{
  return shishi_decrypt_ivupdate_etype (handle, key, keyusage,
					shishi_key_type (key),
					iv, ivlen, ivout, ivoutlen,
					in, inlen, out, outlen);
}

/**
 * shishi_decrypt_iv:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to decrypt with.
 * @keyusage: integer specifying what this key is decrypting.
 * @iv: input array with initialization vector
 * @ivlen: size of input array with initialization vector.
 * @in: input array with data to decrypt.
 * @inlen: size of input array with data to decrypt.
 * @out: output array with newly allocated decrypted data.
 * @outlen: output variable with size of newly allocated output array.
 *
 * Decrypts data using specified initialization vector and key.  The
 * key actually used is derived using the key usage.  If key usage is
 * 0, no key derivation is used.  The OUT buffer must be deallocated
 * by the caller.  The next IV is lost, see
 * shishi_decrypt_ivupdate_etype if you need it.
 *
 * Note that DECRYPT(ENCRYPT(data)) does not necessarily yield data
 * exactly.  Some encryption types add pad to make the data fit into
 * the block size of the encryption algorithm.  Furthermore, the pad
 * is not guaranteed to look in any special way, although existing
 * implementations often pad with the zero byte.  This means that you
 * may have to "frame" data, so it is possible to infer the original
 * length after decryption.  Compare ASN.1 DER which contains such
 * information.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_decrypt_iv (Shishi * handle,
		   Shishi_key * key,
		   int keyusage,
		   const char *iv, size_t ivlen,
		   const char *in, size_t inlen, char **out, size_t * outlen)
{
  return shishi_decrypt_ivupdate_etype (handle, key, keyusage,
					shishi_key_type (key),
					iv, ivlen, NULL, NULL,
					in, inlen, out, outlen);
}

/**
 * shishi_decrypt:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to decrypt with.
 * @keyusage: integer specifying what this key is decrypting.
 * @in: input array with data to decrypt.
 * @inlen: size of input array with data to decrypt.
 * @out: output array with newly allocated decrypted data.
 * @outlen: output variable with size of newly allocated output array.
 *
 * Decrypts data specified key.  The key actually used is derived
 * using the key usage.  If key usage is 0, no key derivation is used.
 * The OUT buffer must be deallocated by the caller.  The default IV
 * is used, see shishi_decrypt_iv if you need to alter it.  The next
 * IV is lost, see shishi_decrypt_ivupdate if you need it.
 *
 * Note that DECRYPT(ENCRYPT(data)) does not necessarily yield data
 * exactly.  Some encryption types add pad to make the data fit into
 * the block size of the encryption algorithm.  Furthermore, the pad
 * is not guaranteed to look in any special way, although existing
 * implementations often pad with the zero byte.  This means that you
 * may have to "frame" data, so it is possible to infer the original
 * length after decryption.  Compare ASN.1 DER which contains such
 * information.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_decrypt (Shishi * handle,
		Shishi_key * key,
		int keyusage,
		const char *in, size_t inlen, char **out, size_t * outlen)
{
  return shishi_decrypt_ivupdate_etype (handle, key, keyusage,
					shishi_key_type (key),
					NULL, 0, NULL, NULL,
					in, inlen, out, outlen);
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
 * http://www.research.att.com/~smb/papers/ides.pdf, although the
 * sample vectors provided by the paper are incorrect.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_n_fold (Shishi * handle,
	       const char *in, size_t inlen, char *out, size_t outlen)
{
  int m = inlen;
  int n = outlen;
  char *buf = NULL;
  char *a = NULL;
  int lcmmn = 0;
  int i = 0;

  /*
     To n-fold a number X, replicate the input value to a length that is
     the least common multiple of n and the length of X. Before each
     repetition, the input is rotated to the right by 13 bit
     positions. The successive n-bit chunks are added together using
     1's-complement addition (that is, addition with end-around carry)
     to yield a n-bit result denoted <X>_n.
   */

  a = xmemdup (in, m);

  lcmmn = lcm (m, n);

  if (VERBOSECRYPTONOISE (handle))
    {
      printf ("%d-fold (string)\n", n * 8);
      printf ("\t ;; string length %d bytes %d bits\n", m, m * 8);
      _shishi_escapeprint (a, m);
      _shishi_hexprint (a, m);
      printf ("\t ;; lcm(%d, %d) = lcm(%d, %d) = %d\n",
	      8 * m, 8 * n, m, n, lcmmn);
    }

  buf = (char *) xmalloc (lcmmn);

  /* Replicate the input th the LCMMN length */
  for (i = 0; i < (lcmmn / m); i++)
    {
      if (VERBOSECRYPTONOISE (handle))
	{
	  printf ("\t ;; %d-th replication\n", i + 1);
	  printf ("string = rot13(string)\n");
	}

      memcpy ((char *) &buf[i * m], a, m);
      rot13 (handle, a, a, m);
    }

  memset (out, 0, n);		/* just in case */

  if (VERBOSECRYPTONOISE (handle))
    {
      printf ("\t ;; replicated string (length %d):\n", lcmmn);
      _shishi_hexprint (buf, lcmmn);
      _shishi_binprint (buf, lcmmn);
      printf ("sum = 0\n");
    }

  /* Now we view the buf as set of n-byte strings
     Add the n-byte long chunks together, using
     one's complement addition, storing the
     result in the output string. */

  for (i = 0; i < (lcmmn / n); i++)
    {
      if (VERBOSECRYPTONOISE (handle))
	{
	  printf ("\t ;; %d-th one's complement addition sum\n", i + 1);
	  printf ("\t ;; sum:\n");
	  _shishi_hexprint (out, n);
	  _shishi_binprint (out, n);
	  printf ("\t ;; A (offset %d):\n", i * n);
	  _shishi_hexprint (&buf[i * n], n);
	  _shishi_binprint (&buf[i * n], n);
	  printf ("sum = ocadd(sum, A);\n");
	}

      ocadd (out, (char *) &buf[i * n], out, n);

      if (VERBOSECRYPTONOISE (handle))
	{
	  printf ("\t ;; sum:\n");
	  _shishi_hexprint (out, n);
	  _shishi_binprint (out, n);
	}
    }

  if (VERBOSECRYPTONOISE (handle))
    {
      printf ("\t ;; nfold\n");
      _shishi_hexprint (out, n);
      _shishi_binprint (out, n);
    }

  free (buf);
  free (a);

  return SHISHI_OK;
}

#define MAX_DR_PRFCONSTANT 1024

/**
 * shishi_dr:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: input array with cryptographic key to use.
 * @prfconstant: input array with the constant string.
 * @prfconstantlen: size of input array with the constant string.
 * @derivedrandom: output array with derived random data.
 * @derivedrandomlen: size of output array with derived random data.
 *
 * Derive "random" data from a key and a constant thusly:
 * DR(KEY, PRFCONSTANT) = TRUNCATE(DERIVEDRANDOMLEN,
 *                                 SHISHI_ENCRYPT(KEY, PRFCONSTANT)).
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_dr (Shishi * handle,
	   Shishi_key * key,
	   const char *prfconstant, size_t prfconstantlen,
	   char *derivedrandom, size_t derivedrandomlen)
{
  char *cipher;
  char plaintext[MAX_DR_PRFCONSTANT];
  char nfoldprfconstant[MAX_DR_PRFCONSTANT];
  size_t blocksize = shishi_cipher_blocksize (shishi_key_type (key));
  size_t totlen, cipherlen;
  int res;

  if (VERBOSECRYPTO (handle))
    {
      printf ("dr (%s, key, prfconstant, %d)\n",
	      shishi_cipher_name (shishi_key_type (key)), derivedrandomlen);
      printf ("\t ;; key (length %d):\n", shishi_key_length (key));
      _shishi_hexprint (shishi_key_value (key), shishi_key_length (key));
      _shishi_binprint (shishi_key_value (key), shishi_key_length (key));
      printf ("\t ;; prfconstant  %s':\n", prfconstant);
      _shishi_escapeprint (prfconstant, prfconstantlen);
      _shishi_hexprint (prfconstant, prfconstantlen);
      _shishi_binprint (prfconstant, prfconstantlen);
    }

  if (prfconstantlen > MAX_DR_PRFCONSTANT)
    return SHISHI_TOO_SMALL_BUFFER;

  if (prfconstantlen == blocksize)
    memcpy (nfoldprfconstant, prfconstant, prfconstantlen);
  else
    {
      res = shishi_n_fold (handle, prfconstant, prfconstantlen,
			   nfoldprfconstant, blocksize);
      if (res != SHISHI_OK)
	return res;
    }

  if (VERBOSECRYPTO (handle))
    {
      printf ("\t ;; possibly nfolded prfconstant (length %d):\n", blocksize);
      _shishi_escapeprint (nfoldprfconstant, blocksize);
      _shishi_hexprint (nfoldprfconstant, blocksize);
      _shishi_binprint (nfoldprfconstant, blocksize);
    }

  memcpy (plaintext, nfoldprfconstant, blocksize);

  totlen = 0;
  do
    {
      res = shishi_encrypt (handle, key, 0, plaintext, blocksize,
			    &cipher, &cipherlen);
      if (res != SHISHI_OK)
	return res;
      if (cipherlen != blocksize)
	return SHISHI_CRYPTO_ERROR;
      memcpy (derivedrandom + totlen, cipher, cipherlen);
      memcpy (plaintext, cipher, cipherlen);
      free (cipher);
      totlen += cipherlen;
    }
  while (totlen < derivedrandomlen);

  if (VERBOSECRYPTO (handle))
    {
      printf ("\t ;; derived random (length %d):\n", derivedrandomlen);
      _shishi_hexprint (derivedrandom, derivedrandomlen);
      _shishi_binprint (derivedrandom, derivedrandomlen);
    }

  return SHISHI_OK;
}

/**
 * shishi_dk:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: input cryptographic key to use.
 * @prfconstant: input array with the constant string.
 * @prfconstantlen: size of input array with the constant string.
 * @derivedkey: pointer to derived key (allocated by caller).
 *
 * Derive a key from a key and a constant thusly:
 * DK(KEY, PRFCONSTANT) = SHISHI_RANDOM-TO-KEY(SHISHI_DR(KEY, PRFCONSTANT)).
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_dk (Shishi * handle,
	   Shishi_key * key,
	   const char *prfconstant, size_t prfconstantlen,
	   Shishi_key * derivedkey)
{
  char rnd[MAX_RANDOM_LEN];
  int res;

  if (VERBOSECRYPTO (handle))
    {
      printf ("dk (%s, key, prfconstant)\n", shishi_key_name (key));
      printf ("\t ;; key (length %d):\n", shishi_key_length (key));
      _shishi_hexprint (shishi_key_value (key), shishi_key_length (key));
      _shishi_binprint (shishi_key_value (key), shishi_key_length (key));
      printf ("\t ;; prfconstant:\n");
      _shishi_escapeprint (prfconstant, prfconstantlen);
      _shishi_hexprint (prfconstant, prfconstantlen);
      _shishi_binprint (prfconstant, prfconstantlen);
    }

  shishi_key_type_set (derivedkey, shishi_key_type (key));

  res = shishi_dr (handle, key, prfconstant, prfconstantlen, rnd,
		   shishi_key_length (derivedkey));
  if (res != SHISHI_OK)
    return res;

  res = shishi_random_to_key (handle, shishi_key_type (derivedkey),
			      rnd, shishi_key_length (derivedkey),
			      derivedkey);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}
