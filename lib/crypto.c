/* crypto.c	crypto functions
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

/* XXX several functions with out/outlen writes longer than the outlen */

#include "internal.h"
#include <gcrypt.h>

static void
escapeprint (const char *str, int len)
{
  int i;

  printf ("\t ;; `");
  for (i = 0; i < len; i++)
    if ((str[i] >= 'A' && str[i] <= 'Z') ||
	(str[i] >= 'a' && str[i] <= 'z') ||
	(str[i] >= '0' && str[i] <= '9') || str[i] == '.')
      printf ("%c", str[i] & 0xFF);
    else
      printf ("\\x%02x", str[i] & 0xFF);
  printf ("' (length %d bytes)\n", len);
}

static void
hexprint (const char *str, int len)
{
  int i;

  printf ("\t ;; ");
  for (i = 0; i < len; i++)
    {
      printf ("%02x ", str[i] & 0xFF);
      if ((i + 1) % 8 == 0)
	printf (" ");
      if ((i + 1) % 16 == 0 && i + 1 < len)
	printf ("\n\t ;; ");
    }
}

static void
binprint (const char *str, int len)
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
bin7print (const char *str, int len)
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
rot13 (Shishi * handle, char *in, char *out, int len)
{
  if (VERBOSECRYPTO (handle))
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

  if (VERBOSECRYPTO (handle))
    {
      printf ("\t ;; rot13 out:\n");
      escapeprint (out, len);
      hexprint (out, len);
      puts ("");
      binprint (out, len);
      puts ("");
    }

  return SHISHI_OK;
}

static int
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

  return SHISHI_OK;
}

static int
simplified_hmac (Shishi * handle,
		 Shishi_key * key,
		 const char *in, size_t inlen,
		 char **outhash, size_t *outhashlen)
{
  gcry_md_hd_t mdh;
  int halg = GCRY_MD_SHA1;
  size_t hlen = gcry_md_get_algo_dlen (halg);
  unsigned char *hash;
  gpg_error_t err;

  err = gcry_md_open (&mdh, halg, GCRY_MD_FLAG_HMAC);
  if (err == GPG_ERR_NO_ERROR)
    err = gcry_md_setkey (mdh, shishi_key_value (key), shishi_key_length (key));
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_GCRYPT_ERROR;
    }

  gcry_md_write (mdh, in, inlen);

  hash = gcry_md_read (mdh, halg);
  if (hash == NULL)
    {
      shishi_error_printf (handle, "Libgcrypt failed to compute hash");
      return SHISHI_GCRYPT_ERROR;
    }

  *outhashlen = hlen;
  *outhash = xmalloc(*outhashlen);
  memcpy(*outhash, hash, *outhashlen);

  gcry_md_close (mdh);

  return SHISHI_OK;
}

static int
simplified_hmac_verify (Shishi * handle,
			Shishi_key * key,
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

  same = (hlen == hmaclen) && memcmp (hash, hmac, hmaclen) == 0;

  free(hash);

  if (!same)
    {
      shishi_error_printf (handle, "HMAC verify failed");
      return SHISHI_CRYPTO_ERROR;
    }

  return SHISHI_OK;
}

typedef enum
{
  SHISHI_DERIVEKEYMODE_CHECKSUM,
  SHISHI_DERIVEKEYMODE_PRIVACY,
  SHISHI_DERIVEKEYMODE_INTEGRITY
}
Shishi_derivekeymode;

static int
simplified_derivekey (Shishi * handle,
		      Shishi_key * key,
		      int keyusage,
		      int derivekeymode,
		      Shishi_key ** outkey)
{
  char constant[5];
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
      hexprint (shishi_key_value (key), shishi_key_length (key));
      puts ("");
    }


  res = shishi_key_from_value (handle, shishi_key_type (key),
			       NULL, &derivedkey);
  if (res != SHISHI_OK)
    return res;

  *outkey = derivedkey;

  if (keyusage)
    {
      uint32_t tmp = htonl (keyusage);
      memcpy (constant, &tmp, 4);
      if (derivekeymode == SHISHI_DERIVEKEYMODE_CHECKSUM)
	constant[4] = '\x99';
      else if (derivekeymode == SHISHI_DERIVEKEYMODE_INTEGRITY)
	constant[4] = '\x55';
      else /* if (derivekeymode == SHISHI_DERIVEKEYMODE_PRIVACY) */
	constant[4] = '\xAA';

      res = shishi_dk (handle, key, constant, 5, derivedkey);
    }
  else
    {
      shishi_key_copy (derivedkey, key);
    }

  if (VERBOSECRYPTO (handle))
    {
      printf ("\t ;; simplified_derivekey out (%d):\n",
	      shishi_key_length (derivedkey));
      hexprint (shishi_key_value (derivedkey),
		shishi_key_length (derivedkey));
      puts ("");
    }

  return res;
}

static int
simplified_dencrypt (Shishi * handle,
		     Shishi_key * key,
		     const char *iv, size_t ivlen,
		     const char *in, size_t inlen,
		     char **out, size_t *outlen,
		     int decryptp)
{
  gcry_cipher_hd_t ch;
  gpg_error_t err;
  int alg = 0;
  int mode = GCRY_CIPHER_MODE_CBC;
  int flags = 0;

  switch (shishi_key_type (key))
    {
    case SHISHI_DES_CBC_CRC:
    case SHISHI_DES_CBC_MD4:
    case SHISHI_DES_CBC_MD5:
      alg = GCRY_CIPHER_DES;
      *outlen = inlen;
      break;

    case SHISHI_DES3_CBC_HMAC_SHA1_KD:
      alg = GCRY_CIPHER_3DES;
      *outlen = inlen;
      break;

    case SHISHI_AES128_CTS_HMAC_SHA1_96:
    case SHISHI_AES256_CTS_HMAC_SHA1_96:
      alg = GCRY_CIPHER_AES;
      flags |= GCRY_CIPHER_CBC_CTS;
      *outlen = inlen;
      break;
    }

  err = gcry_cipher_open (&ch, alg, mode, flags);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf(handle, "Libgcrypt cipher open failed");
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_GCRYPT_ERROR;
    }

  err = gcry_cipher_setkey (ch, shishi_key_value (key),
			    shishi_key_length (key));
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf(handle, "Libgcrypt setkey failed");
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_GCRYPT_ERROR;
    }

  err = gcry_cipher_setiv (ch, iv, ivlen);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_printf(handle, "Libgcrypt setiv failed");
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_GCRYPT_ERROR;
    }

  *out = xmalloc(*outlen);

  if (decryptp)
    err = gcry_cipher_decrypt (ch, (unsigned char *) *out, *outlen,
			       (const unsigned char *) in, inlen);
  else
    err = gcry_cipher_encrypt (ch, (unsigned char *) *out, *outlen,
			       (const unsigned char *) in, inlen);
  if (err != GPG_ERR_NO_ERROR)
    {
      shishi_error_set (handle, gpg_strerror (err));
      return SHISHI_GCRYPT_ERROR;
    }

  gcry_cipher_close (ch);

  return SHISHI_OK;
}

static int
simplified_encrypt (Shishi * handle,
		    Shishi_key * key,
		    int keyusage,
		    const char *iv, size_t ivlen,
		    const char *in, size_t inlen,
		    char **out, size_t *outlen)
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
      int halg = GCRY_MD_SHA1;
      size_t ctlen, ptlen, hmaclen;
      Shishi_key *privacykey = NULL, *integritykey = NULL;

      ptlen = inlen + blen + padzerolen;
      pt = xmalloc (ptlen);

      res = shishi_randomize (handle, pt, blen);
      if (res != SHISHI_OK)
	goto done;

      memcpy (pt + blen, in, inlen);
      memset (pt + blen + inlen, 0, padzerolen);

      res = simplified_derivekey (handle, key, keyusage,
				  SHISHI_DERIVEKEYMODE_PRIVACY,
				  &privacykey);
      if (res != SHISHI_OK)
	goto done;

      res = simplified_dencrypt (handle, privacykey, iv, ivlen,
				 pt, ptlen, &ct, &ctlen, 0);
      if (res != SHISHI_OK)
	goto done;


      res = simplified_derivekey (handle, key, keyusage,
				  SHISHI_DERIVEKEYMODE_INTEGRITY,
				  &integritykey);
      if (res != SHISHI_OK)
	goto done;

      res = simplified_hmac (handle, integritykey, pt, ptlen, &hmac, &hmaclen);
      if (res != SHISHI_OK)
	goto done;

      *outlen = ctlen + hmaclen;
      *out = xmalloc(*outlen);
      memcpy(*out, ct, ctlen);
      memcpy(*out + ctlen, hmac, hmaclen);

    done:
      if (&privacykey)
	shishi_key_done (&privacykey);
      if (&integritykey)
	shishi_key_done (&integritykey);
      if (hmac)
	free (hmac);
      if (ct)
	free (ct);
      if (pt)
	free (pt);
    }
  else
    {
      res = simplified_dencrypt (handle, key, iv, ivlen,
				 in, inlen, out, outlen, 0);
    }

  return res;
}

static int
simplified_decrypt (Shishi * handle,
		    Shishi_key * key,
		    int keyusage,
		    const char *iv, size_t ivlen,
		    const char *in, size_t inlen,
		    char **out, size_t * outlen)
{
  int res;

  if (keyusage)
    {
      Shishi_key *privacykey = NULL, *integritykey = NULL;
      int blen = shishi_cipher_blocksize (shishi_key_type (key));
      int halg = GCRY_MD_SHA1;
      size_t hlen = gcry_md_get_algo_dlen (halg);
      size_t len;

      res = simplified_derivekey (handle, key, keyusage,
				  SHISHI_DERIVEKEYMODE_PRIVACY,
				  &privacykey);
      if (res != SHISHI_OK)
	goto done;

      res = simplified_dencrypt (handle, privacykey, iv, ivlen,
				 in, inlen - hlen, out, outlen, 1);
      if (res != SHISHI_OK)
	goto done;

      res = simplified_derivekey (handle, key, keyusage,
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
      *out = xrealloc(*out, *outlen);

    done:
      if (privacykey)
	shishi_key_done (&privacykey);
      if (integritykey)
	shishi_key_done (&integritykey);
    }
  else
    {
      res = simplified_dencrypt (handle, key, iv, ivlen,
				 in, inlen, out, outlen, 1);
    }

  return res;
}

static int
simplified_checksum (Shishi * handle,
		     Shishi_key * key,
		     int keyusage,
		     char *in, size_t inlen,
		     char **out, size_t *outlen)
{
  Shishi_key *checksumkey;
  int halg = GCRY_MD_SHA1;	/* XXX hide this in crypto-lowlevel.c */
  int hlen = gcry_md_get_algo_dlen (halg);
  int res;

  res = simplified_derivekey (handle, key, keyusage,
			      SHISHI_DERIVEKEYMODE_CHECKSUM,
			      &checksumkey);
  if (res != SHISHI_OK)
    return res;

  res = simplified_hmac (handle, checksumkey, in, inlen, out, outlen);

  shishi_key_done (&checksumkey);

  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

typedef int (*Shishi_random_to_key_function) (Shishi * handle,
					      const char *random,
					      size_t randomlen,
					      Shishi_key * outkey);

typedef int (*Shishi_string_to_key_function) (Shishi * handle,
					      const char *password,
					      size_t passwordlen,
					      const char *salt,
					      size_t saltlen,
					      const char *parameter,
					      Shishi_key * outkey);

typedef int (*Shishi_encrypt_function) (Shishi * handle,
					Shishi_key * key,
					int keyusage,
					const char *iv, size_t ivlen,
					const char *in, size_t inlen,
					char **out, size_t * outlen);

typedef int (*Shishi_decrypt_function) (Shishi * handle,
					Shishi_key * key,
					int keyusage,
					const char *iv, size_t ivlen,
					const char *in, size_t inlen,
					char **out, size_t * outlen);

#include "crypto-null.c"
#include "crypto-des.c"
#include "crypto-3des.c"
#include "crypto-aes.c"

struct cipherinfo
{
  int32_t type;
  char *name;
  int blocksize;
  int minpadsize;
  int confoundersize;
  int keylen;
  int randomlen;
  int defaultcksumtype;
  Shishi_random_to_key_function random2key;
  Shishi_string_to_key_function string2key;
  Shishi_encrypt_function encrypt;
  Shishi_decrypt_function decrypt;
};
typedef struct cipherinfo cipherinfo;

static cipherinfo null_info = {
  0,
  "NULL",
  1,
  0,
  0,
  0,
  0,
  SHISHI_RSA_MD5,
  null_random_to_key,
  null_string_to_key,
  null_encrypt,
  null_decrypt
};

static cipherinfo des_cbc_crc_info = {
  1,
  "des-cbc-crc",
  8,
  4,
  8,
  8,
  8,
  SHISHI_RSA_MD5_DES,
  des_random_to_key,
  des_string_to_key,
  des_crc_encrypt,
  des_crc_decrypt
};

static cipherinfo des_cbc_md4_info = {
  2,
  "des-cbc-md4",
  8,
  0,
  8,
  8,
  8,
  SHISHI_RSA_MD4_DES,
  des_random_to_key,
  des_string_to_key,
  des_md4_encrypt,
  des_md4_decrypt
};

static cipherinfo des_cbc_md5_info = {
  3,
  "des-cbc-md5",
  8,
  0,
  8,
  8,
  8,
  SHISHI_RSA_MD5_DES,
  des_random_to_key,
  des_string_to_key,
  des_md5_encrypt,
  des_md5_decrypt
};

static cipherinfo des_cbc_none_info = {
  4,
  "des-cbc-none",
  8,
  0,
  8,
  3 * 8,
  3 * 8,
  SHISHI_RSA_MD5_DES,
  des_random_to_key,
  des_string_to_key,
  des_none_encrypt,
  des_none_decrypt
};

static cipherinfo des3_cbc_sha1_kd_info = {
  16,
  "des3-cbc-sha1-kd",
  8,
  0,
  8,
  3 * 8,
  3 * 8,
  SHISHI_HMAC_SHA1_DES3_KD,
  des3_random_to_key,
  des3_string_to_key,
  des3_encrypt,
  des3_decrypt
};

static cipherinfo des3_cbc_none_info = {
  6,
  "des3-cbc-none",
  8,
  0,
  8,
  3 * 8,
  3 * 8,
  SHISHI_HMAC_SHA1_DES3_KD,
  des3_random_to_key,
  des3_string_to_key,
  des3none_encrypt,
  des3none_decrypt
};

static cipherinfo aes128_cts_hmac_sha1_96_info = {
  17,
  "aes128-cts-hmac-sha1-96",
  16,
  0,
  16,
  128 / 8,
  128 / 8,
  SHISHI_HMAC_SHA1_96_AES128,
  aes128_random_to_key,
  aes128_string_to_key,
  aes128_encrypt,
  aes128_decrypt
};

static cipherinfo aes256_cts_hmac_sha1_96_info = {
  18,
  "aes256-cts-hmac-sha1-96",
  16,
  0,
  16,
  256 / 8,
  256 / 8,
  SHISHI_HMAC_SHA1_96_AES256,
  aes256_random_to_key,
  aes256_string_to_key,
  aes256_encrypt,
  aes256_decrypt
};

static cipherinfo *ciphers[] = {
  &null_info,
  &des_cbc_crc_info,
  &des_cbc_md4_info,
  &des_cbc_md5_info,
  &des_cbc_none_info,
  &des3_cbc_none_info,
  &des3_cbc_sha1_kd_info,
  &aes128_cts_hmac_sha1_96_info,
  &aes256_cts_hmac_sha1_96_info
};

int
_shishi_cipher_init (void)
{
  if (gcry_control (GCRYCTL_ANY_INITIALIZATION_P) == 0)
    {
      if (gcry_check_version (GCRYPT_VERSION) == NULL)
	return SHISHI_GCRYPT_ERROR;
      if (gcry_control (GCRYCTL_DISABLE_SECMEM, NULL, 0) != GPG_ERR_NO_ERROR)
	return SHISHI_GCRYPT_ERROR;
      if (gcry_control (GCRYCTL_INITIALIZATION_FINISHED,
			NULL, 0) != GPG_ERR_NO_ERROR)
	return SHISHI_GCRYPT_ERROR;
    }

  return SHISHI_OK;
}

/**
 * shishi_cipher_supported_p:
 * @type: encryption type, see Shishi_etype.
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
 * shishi_cipher_minpadsize:
 * @type: encryption type, see Shishi_etype.
 *
 * Return value: Return the minimum pad size for encryption type, as
 * defined in the standards.
 **/
int
shishi_cipher_minpadsize (int32_t type)
{
  size_t i;

  for (i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
    if (type == ciphers[i]->type)
      return ciphers[i]->minpadsize;

  return -1;
}

/**
 * shishi_cipher_confoundersize:
 * @type: encryption type, see Shishi_etype.
 *
 * Return value: Returns the size of the confounder (random data) for
 * encryption type, as defined in the standards.
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
 * Return value: Return length of random used for the encryption type,
 * as defined in the standards.
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

/**
 * shishi_cipher_parse:
 * @cipher: name of encryption type, e.g. "des3-cbc-sha1-kd".
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
		      const char *parameter,
		      Shishi_key * outkey)
{
  Shishi_string_to_key_function string2key;
  int res;

  shishi_key_type_set (outkey, keytype);

  if (VERBOSECRYPTO (handle))
    {
      printf ("string_to_key (%s, password, salt)\n",
	      shishi_key_name (outkey));
      printf ("\t ;; password:\n");
      escapeprint (password, passwordlen);
      hexprint (password, passwordlen);
      puts ("");
      printf ("\t ;; salt:\n");
      escapeprint (salt, saltlen);
      hexprint (salt, saltlen);
      puts ("");
    }

  string2key = _shishi_cipher_string_to_key (shishi_key_type (outkey));
  if (string2key == NULL)
    {
      shishi_error_printf (handle, "Unsupported keytype %d",
			   shishi_key_type (outkey));
      return !SHISHI_OK;
    }

  res = (*string2key) (handle, password, passwordlen,
		       salt, saltlen, parameter, outkey);

  if (VERBOSECRYPTO (handle))
    {
      printf ("\t ;; string_to_key key:\n");
      hexprint (shishi_key_value (outkey), shishi_key_length (outkey));
      puts ("");
      binprint (shishi_key_value (outkey), shishi_key_length (outkey));
      puts ("");
    }

  return res;
}

/**
 * shishi_random_to_key:
 * @handle: shishi handle as allocated by shishi_init().
 * @keytype: cryptographic encryption type, see Shishi_etype.
 * @random: input array with random data.
 * @randomlen: length of input array with random data.
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
		      char *random, size_t randomlen,
		      Shishi_key * outkey)
{
  Shishi_random_to_key_function random2key;
  int res;

  shishi_key_type_set (outkey, keytype);

  if (VERBOSECRYPTO (handle))
    {
      printf ("random_to_key (%s, random)\n", shishi_key_name (outkey));
      printf ("\t ;; random:\n");
      hexprint (random, randomlen);
      puts ("");
      binprint (random, randomlen);
      puts ("");
    }

  random2key = _shishi_cipher_random_to_key (keytype);
  if (random2key == NULL)
    {
      shishi_error_printf (handle, "Unsupported random_to_key() ekeytype %d",
			   keytype);
      return !SHISHI_OK;
    }

  res = (*random2key) (handle, random, randomlen, outkey);

  if (VERBOSECRYPTO (handle))
    {
      printf ("\t ;; random_to_key key:\n");
      hexprint (shishi_key_value (outkey), shishi_key_length (outkey));
      puts ("");
      binprint (shishi_key_value (outkey), shishi_key_length (outkey));
      puts ("");
    }

  return res;
}

/**
 * shishi_checksum:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to encrypt with.
 * @keyusage: integer specifying what this key is encrypting.
 * @cksumtype: the checksum algorithm to use.
 * @in: input array with data to integrity protect.
 * @inlen: size of input array with data to integrity protect.
 * @out: output array with integrity protected data.
 * @outlen: on input, holds maximum size of output array, on output,
 *          holds actual size of output array.
 *
 * Integrity protect data using key, possibly altered by supplied key
 * usage.  If key usage is 0, no key derivation is used.
 *
 * If OUT is NULL, this functions only set OUTLEN.  This usage may be
 * used by the caller to allocate the proper buffer size.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_checksum (Shishi * handle,
		 Shishi_key * key,
		 int keyusage,
		 int cksumtype,
		 char *in, size_t inlen,
		 char **out, size_t *outlen)
{
  int res;

  if (VERBOSECRYPTO (handle))
    {
      printf ("checksum (%s, %d, in, out)\n",
	      shishi_key_name (key), cksumtype);
      printf ("\t ;; key (%d):\n", shishi_key_length (key));
      hexprint (shishi_key_value (key), shishi_key_length (key));
      puts ("");
      printf ("\t ;; in:\n");
      escapeprint (in, inlen);
      hexprint (in, inlen);
      puts ("");
    }

  if (cksumtype == 0)
    cksumtype = shishi_cipher_defaultcksumtype (shishi_key_type (key));

  /* XXX create a dispatcher instead of hardcoding this */

  switch (cksumtype)
    {
    case SHISHI_RSA_MD4_DES:
      {
	char buffer[BUFSIZ];
	int buflen;
	char *keyp;
	int i;

	buflen = sizeof (buffer);
	res = checksum_md4 (handle, buffer, &buflen, in, inlen);
	if (res != SHISHI_OK)
	  {
	    shishi_error_set (handle, "checksum failed");
	    return res;
	  }

	keyp = shishi_key_value (key);

	for (i = 0; i < 8; i++)
	  keyp[i] ^= 0xF0;

	res = simplified_dencrypt (handle, key, NULL, 0, buffer, buflen,
				   out, outlen, 0);

	for (i = 0; i < 8; i++)
	  keyp[i] ^= 0xF0;

	if (res != SHISHI_OK)
	  {
	    shishi_error_set (handle, "encrypt failed");
	    return res;
	  }
      }
      break;

    case SHISHI_RSA_MD5_DES:
      {
	char buffer[BUFSIZ];
	int buflen;
	char *keyp;
	int i;

	buflen = sizeof (buffer);
	res = checksum_md5 (handle, buffer, &buflen, in, inlen);
	if (res != SHISHI_OK)
	  {
	    shishi_error_set (handle, "checksum failed");
	    return res;
	  }

	keyp = shishi_key_value (key);

	for (i = 0; i < 8; i++)
	  keyp[i] ^= 0xF0;

	res = simplified_dencrypt (handle, key, NULL, 0, buffer, buflen,
				   out, outlen, 0);

	for (i = 0; i < 8; i++)
	  keyp[i] ^= 0xF0;

	if (res != SHISHI_OK)
	  {
	    shishi_error_set (handle, "encrypt failed");
	    return res;
	  }
      }
      break;

    case SHISHI_HMAC_SHA1_DES3_KD:
      res = simplified_checksum (handle, key, keyusage,
				 in, inlen, out, outlen);
      break;

    case SHISHI_HMAC_SHA1_96_AES128:
      res = simplified_checksum (handle, key, keyusage,
			     in, inlen, out, outlen);
      *outlen = 96 / 8;
      break;

    case SHISHI_HMAC_SHA1_96_AES256:
      res = simplified_checksum (handle, key, keyusage,
				 in, inlen, out, outlen);
      *outlen = 96 / 8;
      break;

    case 42:
      {
	char buffer[BUFSIZ];
	int buflen;
	char *keyp;
	char *p;
	int i;
	gcry_md_hd_t hd;
	gcry_cipher_hd_t ch;

	gcry_md_open (&hd, GCRY_MD_MD5, 0);
	if (!hd)
	  return SHISHI_GCRYPT_ERROR;

	gcry_md_write (hd, in, inlen);
	p = gcry_md_read (hd, GCRY_MD_MD5);

	keyp = shishi_key_value (key);

	gcry_cipher_open (&ch, GCRY_CIPHER_DES,
			       GCRY_CIPHER_MODE_CBC,
			       GCRY_CIPHER_CBC_MAC);
	if (ch == NULL)
	  return SHISHI_GCRYPT_ERROR;

	res = gcry_cipher_setkey (ch, keyp, 8);
	if (res != GPG_ERR_NO_ERROR)
	  return SHISHI_GCRYPT_ERROR;

	res = gcry_cipher_setiv (ch, NULL, 8);
	if (res != 0)
	  return SHISHI_GCRYPT_ERROR;

	*outlen = 8;
	*out = xmalloc(*outlen);

	res = gcry_cipher_encrypt (ch, *out, *outlen, p, 16);
	if (res != 0)
	  return SHISHI_GCRYPT_ERROR;

	gcry_cipher_close (ch);
	gcry_md_close (hd);
      }
      break;

    default:
      shishi_error_printf (handle, "Unsupported checksum type %d",
			   shishi_key_type (key));
      res = SHISHI_CRYPTO_ERROR;
      break;
    }

  if (VERBOSECRYPTO (handle))
    {
      printf ("\t ;; checksum out:\n");
      escapeprint (*out, *outlen);
      hexprint (*out, *outlen);
      puts ("");
    }

  return res;
}

/**
 * shishi_encrypt_iv_etype:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to encrypt with.
 * @keyusage: integer specifying what this key is encrypting.
 * @etype: integer specifying what decryption method to use.
 * @iv: input array with initialization vector.
 * @ivlen: size of input array with initialization vector.
 * @in: input array with data to encrypt.
 * @inlen: size of input array with data to encrypt.
 * @out: output array with encrypted data.
 * @outlen: on input, holds maximum size of output array, on output,
 *          holds actual size of output array.
 *
 * Encrypts data using key, possibly altered by supplied key usage.
 * If key usage is 0, no key derivation is used.
 *
 * If OUT is NULL, this functions only set OUTLEN.  This usage may be
 * used by the caller to allocate the proper buffer size.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_encrypt_iv_etype (Shishi * handle,
			 Shishi_key * key,
			 int keyusage,
			 int32_t etype,
			 char *iv, size_t ivlen,
			 char *in, size_t inlen,
			 char **out, size_t *outlen)
{
  Shishi_encrypt_function encrypt;
  int res;

  if (VERBOSECRYPTO (handle))
    {
      printf ("encrypt (type=%s, usage=%d, key, in)\n",
	      shishi_key_name (key), keyusage);
      printf ("\t ;; key (%d):\n", shishi_key_length (key));
      hexprint (shishi_key_value (key), shishi_key_length (key));
      puts ("");
      printf ("\t ;; in (%d):\n", inlen);
      escapeprint (in, inlen);
      hexprint (in, inlen);
      puts ("");
    }

  encrypt = _shishi_cipher_encrypt (etype);
  if (encrypt == NULL)
    {
      shishi_error_printf (handle, "Unsupported keytype %d",
			   shishi_key_type (key));
      return SHISHI_CRYPTO_ERROR;
    }

  res = (*encrypt) (handle, key, keyusage, iv, ivlen, in, inlen, out, outlen);

  if (VERBOSECRYPTO (handle))
    {
      printf ("\t ;; encrypt out:\n");
      escapeprint (*out, *outlen);
      hexprint (*out, *outlen);
      puts ("");
    }

  return res;
}

/**
 * shishi_encrypt:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to encrypt with.
 * @keyusage: integer specifying what this key is encrypting.
 * @in: input array with data to encrypt.
 * @inlen: size of input array with data to encrypt.
 * @out: output array with encrypted data.
 * @outlen: on input, holds maximum size of output array, on output,
 *          holds actual size of output array.
 *
 * Encrypts data using key, possibly altered by supplied key usage.
 * If key usage is 0, no key derivation is used.
 *
 * If OUT is NULL, this functions only set OUTLEN.  This usage may be
 * used by the caller to allocate the proper buffer size.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_encrypt_iv (Shishi * handle,
		   Shishi_key * key,
		   int keyusage,
		   char *iv, size_t ivlen,
		   char *in, size_t inlen,
		   char **out, size_t *outlen)
{
  return shishi_encrypt_iv_etype (handle, key, keyusage, shishi_key_type (key),
				  NULL, 0, in, inlen, out, outlen);
}

/**
 * shishi_encrypt:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to encrypt with.
 * @keyusage: integer specifying what this key is encrypting.
 * @in: input array with data to encrypt.
 * @inlen: size of input array with data to encrypt.
 * @out: output array with encrypted data.
 * @outlen: on input, holds maximum size of output array, on output,
 *          holds actual size of output array.
 *
 * Encrypts data using key, possibly altered by supplied key usage.
 * If key usage is 0, no key derivation is used.
 *
 * If OUT is NULL, this functions only set OUTLEN.  This usage may be
 * used by the caller to allocate the proper buffer size.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_encrypt (Shishi * handle,
		Shishi_key * key,
		int keyusage,
		char *in, size_t inlen,
		char **out, size_t *outlen)
{
  return shishi_encrypt_iv (handle, key, keyusage, NULL, 0,
			    in, inlen, out, outlen);
}

/**
 * shishi_decrypt_iv_etype:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to decrypt with.
 * @keyusage: integer specifying what this key is decrypting.
 * @etype: integer specifying what decryption method to use.
 * @iv: input array with initialization vector.
 * @ivlen: size of input array with initialization vector.
 * @in: input array with data to decrypt.
 * @inlen: size of input array with data to decrypt.
 * @out: output array with decrypted data.
 * @outlen: on input, holds maximum size of output array, on output,
 *          holds actual size of output array.
 *
 * Decrypts data using key, possibly altered by supplied key usage.
 * If key usage is 0, no key derivation is used.
 *
 * If OUT is NULL, this functions only set OUTLEN.  This usage may be
 * used by the caller to allocate the proper buffer size.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_decrypt_iv_etype (Shishi * handle,
			 Shishi_key * key,
			 int keyusage,
			 int32_t etype,
			 char *iv, size_t ivlen,
			 char *in, size_t inlen,
			 char **out, size_t *outlen)
{
  Shishi_decrypt_function decrypt;
  int res;

  if (VERBOSECRYPTO (handle))
    {
      printf ("decrypt (type=%s, usage=%d, key, in, out)\n",
	      shishi_key_name (key), keyusage);
      printf ("\t ;; key (%d):\n", shishi_key_length (key));
      hexprint (shishi_key_value (key), shishi_key_length (key));
      puts ("");
      printf ("\t ;; in (%d):\n", inlen);
      escapeprint (in, inlen);
      hexprint (in, inlen);
      puts ("");
    }

  decrypt = _shishi_cipher_decrypt (etype);
  if (decrypt == NULL)
    {
      shishi_error_printf (handle, "Unsupported keytype %d",
			   shishi_key_type (key));
      return SHISHI_CRYPTO_ERROR;
    }

  res = (*decrypt) (handle, key, keyusage, iv, ivlen, in, inlen, out, outlen);

  if (VERBOSECRYPTO (handle))
    {
      printf ("\t ;; decrypt out:\n");
      escapeprint (*out, *outlen);
      hexprint (*out, *outlen);
      puts ("");
    }

  return res;
}

/**
 * shishi_decrypt_iv:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to decrypt with.
 * @keyusage: integer specifying what this key is decrypting.
 * @iv: input array with initialization vector.
 * @ivlen: size of input array with initialization vector.
 * @in: input array with data to decrypt.
 * @inlen: size of input array with data to decrypt.
 * @out: output array with decrypted data.
 * @outlen: on input, holds maximum size of output array, on output,
 *          holds actual size of output array.
 *
 * Decrypts data using key, possibly altered by supplied key usage.
 * If key usage is 0, no key derivation is used.
 *
 * If OUT is NULL, this functions only set OUTLEN.  This usage may be
 * used by the caller to allocate the proper buffer size.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_decrypt_iv (Shishi * handle,
		   Shishi_key * key,
		   int keyusage,
		   char *iv, size_t ivlen,
		   char *in, size_t inlen,
		   char **out, size_t *outlen)
{
  return shishi_decrypt_iv_etype (handle, key, keyusage,
				  shishi_key_type (key),
				  iv, ivlen,
				  in, inlen,
				  out, outlen);
}

/**
 * shishi_decrypt:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to decrypt with.
 * @keyusage: integer specifying what this key is decrypting.
 * @in: input array with data to decrypt.
 * @inlen: size of input array with data to decrypt.
 * @out: output array with decrypted data.
 * @outlen: on input, holds maximum size of output array, on output,
 *          holds actual size of output array.
 *
 * Decrypts data using key, possibly altered by supplied key usage.
 * If key usage is 0, no key derivation is used.
 *
 * If OUT is NULL, this functions only set OUTLEN.  This usage may be
 * used by the caller to allocate the proper buffer size.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_decrypt (Shishi * handle,
		Shishi_key * key,
		int keyusage,
		char *in, size_t inlen,
		char **out, size_t *outlen)
{
  return shishi_decrypt_iv (handle, key, keyusage, NULL, 0,
			    in, inlen, out, outlen);
}

/**
 * shishi_randomize:
 * @handle: shishi handle as allocated by shishi_init().
 * @data: output array to be filled with random data.
 * @datalen: size of output array.
 *
 * Store cryptographically strong random data of given size in the
 * provided buffer.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_randomize (Shishi * handle, char *data, size_t datalen)
{
#define RAND_TEST_SIZE 42
  char old[RAND_TEST_SIZE];

  memcpy (data, old, datalen < RAND_TEST_SIZE ? datalen : RAND_TEST_SIZE);

  gcry_randomize (data, datalen, GCRY_STRONG_RANDOM);

  if (datalen > 0 &&
      memcmp (data, old,
	      datalen < RAND_TEST_SIZE ? datalen : RAND_TEST_SIZE) == 0)
    {
      shishi_error_set (handle, "No random data collected.");
      return SHISHI_GCRYPT_ERROR;
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
	       char *in, size_t inlen,
	       char *out, size_t outlen)
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

  a = (char *) malloc (m);
  if (a == NULL)
    return SHISHI_MALLOC_ERROR;
  memcpy (a, in, m);

  lcmmn = lcm (m, n);

  if (VERBOSECRYPTO (handle))
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
      if (VERBOSECRYPTO (handle))
	{
	  printf ("\t ;; %d-th replication\n", i + 1);
	  printf ("string = rot13(string)\n");
	}

      memcpy ((char *) &buf[i * m], a, m);
      rot13 (handle, a, a, m);

      if (VERBOSECRYPTO (handle))
	puts ("");
    }

  memset (out, 0, n);		/* just in case */

  if (VERBOSECRYPTO (handle))
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
      if (VERBOSECRYPTO (handle))
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

      if (VERBOSECRYPTO (handle))
	{
	  printf ("\t ;; sum:\n");
	  hexprint (out, n);
	  puts ("");
	  binprint (out, n);
	  puts ("");
	  puts ("");
	}
    }

  if (VERBOSECRYPTO (handle))
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
	   Shishi_key * key,
	   char *constant, size_t constantlen,
	   char *derivedrandom, size_t derivedrandomlen)
{
  char *cipher;
  char plaintext[MAX_DR_CONSTANT];
  char nfoldconstant[MAX_DR_CONSTANT];
  int blocksize = shishi_cipher_blocksize (shishi_key_type (key));
  size_t totlen, cipherlen;
  int res;

  if (VERBOSECRYPTO (handle))
    {
      printf ("dr (%s, key, constant, %d)\n",
	      shishi_cipher_name (shishi_key_type (key)), derivedrandomlen);
      printf ("\t ;; key (length %d):\n", shishi_key_type (key));
      hexprint (shishi_key_value (key), shishi_key_type (key));
      puts ("");
      binprint (shishi_key_value (key), shishi_key_type (key));
      puts ("");
      printf ("\t ;; constant  %s':\n", constant);
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

  if (VERBOSECRYPTO (handle))
    {
      printf ("\t ;; possibly nfolded constant (length %d):\n", blocksize);
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
	   Shishi_key * key,
	   char *constant, int constantlen, Shishi_key * derivedkey)
{
  char random[MAX_RANDOM_LEN];
  int res;

  if (VERBOSECRYPTO (handle))
    {
      printf ("dk (%s, key, constant)\n", shishi_key_name (key));
      printf ("\t ;; key (length %d):\n", shishi_key_length (key));
      hexprint (shishi_key_value (key), shishi_key_length (key));
      puts ("");
      binprint (shishi_key_value (key), shishi_key_length (key));
      puts ("");
      printf ("\t ;; constant:\n");
      escapeprint (constant, constantlen);
      hexprint (constant, constantlen);
      puts ("");
      binprint (constant, constantlen);
      puts ("");
      puts ("");
    }

  shishi_key_type_set (derivedkey, shishi_key_type (key));

  res = shishi_dr (handle, key, constant, constantlen, random,
		   shishi_key_length (derivedkey));
  if (res != SHISHI_OK)
    return res;

  res = shishi_random_to_key (handle, shishi_key_type (derivedkey),
			      random, shishi_key_length (derivedkey),
			      derivedkey);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}
