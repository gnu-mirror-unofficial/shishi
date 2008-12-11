/* low-crypto.c --- Shishi crypto wrappers around generic crypto.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008  Simon Josefsson
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
#include "gc.h"
#include "arcfour.h"
#include <gcrypt.h>
#include "crc.h"
#include "low-crypto.h"

int
_shishi_crypto_init (Shishi * handle)
{
  int rc = gc_init ();

  if (rc != GC_OK)
    return SHISHI_CRYPTO_INTERNAL_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_randomize:
 * @handle: shishi handle as allocated by shishi_init().
 * @strong: 0 iff operation should not block, non-0 for very strong randomness.
 * @data: output array to be filled with random data.
 * @datalen: size of output array.
 *
 * Store cryptographically random data of given size in the provided
 * buffer.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_randomize (Shishi * handle, int strong, void *data, size_t datalen)
{
  Gc_rc rc;

  if (strong)
    rc = gc_random (data, datalen);
  else
    rc = gc_pseudo_random (data, datalen);

  if (rc != GC_OK)
    return SHISHI_FILE_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_crc:
 * @handle: shishi handle as allocated by shishi_init().
 * @in: input character array of data to checksum.
 * @inlen: length of input character array of data to checksum.
 * @out: newly allocated character array with checksum of data.
 *
 * Compute checksum of data using CRC32 modified according to RFC
 * 1510.  The @out buffer must be deallocated by the caller.
 *
 * The modifications compared to standard CRC32 is that no initial and
 * final XOR is performed, and that the output is returned in
 * LSB-first order.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_crc (Shishi * handle, const char *in, size_t inlen, char *out[4])
{
  uint32_t crc = crc32_update_no_xor (0, in, inlen);

  *out = xmalloc (4);
  (*out)[0] = crc & 0xFF;
  (*out)[1] = (crc >> 8) & 0xFF;
  (*out)[2] = (crc >> 16) & 0xFF;
  (*out)[3] = (crc >> 24) & 0xFF;

  return SHISHI_OK;
}

/**
 * shishi_md4:
 * @handle: shishi handle as allocated by shishi_init().
 * @in: input character array of data to hash.
 * @inlen: length of input character array of data to hash.
 * @out: newly allocated character array with hash of data.
 *
 * Compute hash of data using MD4.  The @out buffer must be
 * deallocated by the caller.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_md4 (Shishi * handle,
	    const char *in, size_t inlen, char *out[16])
{
  Gc_rc rc;

  *out = xmalloc (GC_MD4_DIGEST_SIZE);
  rc = gc_md4 (in, inlen, *out);
  if (rc != GC_OK)
    return SHISHI_CRYPTO_INTERNAL_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_md5:
 * @handle: shishi handle as allocated by shishi_init().
 * @in: input character array of data to hash.
 * @inlen: length of input character array of data to hash.
 * @out: newly allocated character array with hash of data.
 *
 * Compute hash of data using MD5.  The @out buffer must be
 * deallocated by the caller.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_md5 (Shishi * handle,
	    const char *in, size_t inlen, char *out[16])
{
  Gc_rc rc;

  *out = xmalloc (GC_MD5_DIGEST_SIZE);
  rc = gc_md5 (in, inlen, *out);
  if (rc != GC_OK)
    return SHISHI_CRYPTO_INTERNAL_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_hmac_md5:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: input character array with key to use.
 * @keylen: length of input character array with key to use.
 * @in: input character array of data to hash.
 * @inlen: length of input character array of data to hash.
 * @outhash: newly allocated character array with keyed hash of data.
 *
 * Compute keyed checksum of data using HMAC-MD5.  The @outhash buffer
 * must be deallocated by the caller.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_hmac_md5 (Shishi * handle,
		 const char *key, size_t keylen,
		 const char *in, size_t inlen, char *outhash[16])
{
  Gc_rc rc;

  *outhash = xmalloc (GC_MD5_DIGEST_SIZE);
  rc = gc_hmac_md5 (key, keylen, in, inlen, *outhash);
  if (rc != GC_OK)
    return SHISHI_CRYPTO_INTERNAL_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_hmac_sha1:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: input character array with key to use.
 * @keylen: length of input character array with key to use.
 * @in: input character array of data to hash.
 * @inlen: length of input character array of data to hash.
 * @outhash: newly allocated character array with keyed hash of data.
 *
 * Compute keyed checksum of data using HMAC-SHA1.  The @outhash
 * buffer must be deallocated by the caller.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_hmac_sha1 (Shishi * handle,
		  const char *key, size_t keylen,
		  const char *in, size_t inlen,
		  char *outhash[20])
{
  Gc_rc rc;

  *outhash = xmalloc (GC_SHA1_DIGEST_SIZE);
  rc = gc_hmac_sha1 (key, keylen, in, inlen, *outhash);
  if (rc != GC_OK)
    return SHISHI_CRYPTO_INTERNAL_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_des_cbc_mac:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: input character array with key to use.
 * @iv: input character array with initialization vector to use, can be NULL.
 * @in: input character array of data to hash.
 * @inlen: length of input character array of data to hash.
 * @out: newly allocated character array with keyed hash of data.
 *
 * Computed keyed checksum of data using DES-CBC-MAC.  The @out buffer
 * must be deallocated by the caller.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
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

  res = SHISHI_OK;

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

/**
 * shishi_arcfour:
 * @handle: shishi handle as allocated by shishi_init().
 * @decryptp: 0 to indicate encryption, non-0 to indicate decryption.
 * @key: input character array with key to use.
 * @keylen: length of input key array.
 * @iv: input character array with initialization vector to use, or NULL.
 * @ivout: output character array with updated initialization vector, or NULL.
 * @in: input character array of data to encrypt/decrypt.
 * @inlen: length of input character array of data to encrypt/decrypt.
 * @out: newly allocated character array with encrypted/decrypted data.
 *
 * Encrypt or decrypt data (depending on @decryptp) using ARCFOUR.
 * The @out buffer must be deallocated by the caller.
 *
 * The "initialization vector" used here is the concatenation of the
 * sbox and i and j, and is thus always of size 256 + 1 + 1.  This is
 * a slight abuse of terminology, and assumes you know what you are
 * doing.  Don't use it if you can avoid to.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_arcfour (Shishi * handle, int decryptp,
		const char *key, size_t keylen,
		const char iv[258], char *ivout[258],
		const char *in, size_t inlen, char **out)
{
  arcfour_context ctx;

  *out = xmalloc (inlen);

  if (iv)
    memcpy (&ctx, iv, sizeof (ctx));
  else
    arcfour_setkey (&ctx, key, keylen);

  arcfour_stream (&ctx, in, *out, inlen);

  if (ivout)
    {
      *ivout = xmalloc (sizeof (ctx));
      memcpy (*ivout, &ctx, sizeof (ctx));
    }

  return SHISHI_OK;
}

/**
 * shishi_des:
 * @handle: shishi handle as allocated by shishi_init().
 * @decryptp: 0 to indicate encryption, non-0 to indicate decryption.
 * @key: input character array with key to use.
 * @iv: input character array with initialization vector to use, or NULL.
 * @ivout: output character array with updated initialization vector, or NULL.
 * @in: input character array of data to encrypt/decrypt.
 * @inlen: length of input character array of data to encrypt/decrypt.
 * @out: newly allocated character array with encrypted/decrypted data.
 *
 * Encrypt or decrypt data (depending on @decryptp) using DES in CBC
 * mode.  The @out buffer must be deallocated by the caller.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_des (Shishi * handle, int decryptp,
	    const char key[8],
	    const char iv[8],
	    char *ivout[8],
	    const char *in, size_t inlen, char **out)
{
  return libgcrypt_dencrypt (handle, GCRY_CIPHER_DES, 0, GCRY_CIPHER_MODE_CBC,
			     decryptp, key, 8, iv, ivout, in, inlen, out);
}

/**
 * shishi_3des:
 * @handle: shishi handle as allocated by shishi_init().
 * @decryptp: 0 to indicate encryption, non-0 to indicate decryption.
 * @key: input character array with key to use.
 * @iv: input character array with initialization vector to use, or NULL.
 * @ivout: output character array with updated initialization vector, or NULL.
 * @in: input character array of data to encrypt/decrypt.
 * @inlen: length of input character array of data to encrypt/decrypt.
 * @out: newly allocated character array with encrypted/decrypted data.
 *
 * Encrypt or decrypt data (depending on @decryptp) using 3DES in CBC
 * mode.  The @out buffer must be deallocated by the caller.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_3des (Shishi * handle, int decryptp,
	     const char key[8],
	     const char iv[8],
	     char *ivout[8],
	     const char *in, size_t inlen, char **out)
{
  return libgcrypt_dencrypt (handle, GCRY_CIPHER_3DES, 0,
			     GCRY_CIPHER_MODE_CBC, decryptp, key, 24, iv,
			     ivout, in, inlen, out);
}

/**
 * shishi_aes_cts:
 * @handle: shishi handle as allocated by shishi_init().
 * @decryptp: 0 to indicate encryption, non-0 to indicate decryption.
 * @key: input character array with key to use.
 * @keylen: length of input character array with key to use.
 * @iv: input character array with initialization vector to use, or NULL.
 * @ivout: output character array with updated initialization vector, or NULL.
 * @in: input character array of data to encrypt/decrypt.
 * @inlen: length of input character array of data to encrypt/decrypt.
 * @out: newly allocated character array with encrypted/decrypted data.
 *
 * Encrypt or decrypt data (depending on @decryptp) using AES in
 * CBC-CTS mode.  The length of the key, @keylen, decide if AES 128 or
 * AES 256 should be used.  The @out buffer must be deallocated by the
 * caller.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_aes_cts (Shishi * handle, int decryptp,
		const char *key, size_t keylen,
		const char iv[16],
		char *ivout[16],
		const char *in, size_t inlen, char **out)
{
  return libgcrypt_dencrypt (handle, GCRY_CIPHER_AES, GCRY_CIPHER_CBC_CTS,
			     GCRY_CIPHER_MODE_CBC, decryptp,
			     key, keylen, iv, ivout, in, inlen, out);
}

/**
 * shishi_pbkdf2_sha1:
 * @handle: shishi handle as allocated by shishi_init().
 * @P: input password, an octet string
 * @Plen: length of password, an octet string
 * @S: input salt, an octet string
 * @Slen: length of salt, an octet string
 * @c: iteration count, a positive integer
 * @dkLen: intended length in octets of the derived key, a positive integer,
 *   at most (2^32 - 1) * hLen.  The DK array must have room for this many
 *   characters.
 * @DK: output derived key, a dkLen-octet string
 *
 * Derive key using the PBKDF2 defined in PKCS5.  PBKDF2 applies a
 * pseudorandom function to derive keys. The length of the derived key
 * is essentially unbounded. (However, the maximum effective search
 * space for the derived key may be limited by the structure of the
 * underlying pseudorandom function, which is this function is always
 * SHA1.)
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_pbkdf2_sha1 (Shishi * handle,
		    const char *P, size_t Plen,
		    const char *S, size_t Slen,
		    unsigned int c, unsigned int dkLen, char *DK)
{
  Gc_rc rc;

  rc = gc_pbkdf2_sha1 (P, Plen, S, Slen, c, DK, dkLen);

  if (rc == GC_PKCS5_INVALID_ITERATION_COUNT)
    return SHISHI_PKCS5_INVALID_ITERATION_COUNT;

  if (rc == GC_PKCS5_INVALID_DERIVED_KEY_LENGTH)
    return SHISHI_PKCS5_INVALID_DERIVED_KEY_LENGTH;

  if (rc == GC_PKCS5_DERIVED_KEY_TOO_LONG)
    return SHISHI_PKCS5_DERIVED_KEY_TOO_LONG;

  if (rc != GC_OK)
    return SHISHI_CRYPTO_INTERNAL_ERROR;

  return SHISHI_OK;
}
