/* crypto-ctx.c   high-level crypto functions
 * Copyright (C) 2002, 2003, 2007  Simon Josefsson
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

struct Shishi_crypto
{
  Shishi *handle;
  Shishi_key *key;
  int keyusage;
  int32_t etype;
  char *iv;
  size_t ivlen;
};

/**
 * shishi_crypto:
 * @handle: shishi handle as allocated by shishi_init().
 * @key: key to encrypt with.
 * @keyusage: integer specifying what this key will encrypt/decrypt.
 * @etype: integer specifying what cipher to use.
 * @iv: input array with initialization vector
 * @ivlen: size of input array with initialization vector.
 *
 * Initialize a crypto context.  This store a key, keyusage,
 * encryption type and initialization vector in a "context", and the
 * caller can then use this context to perform encryption via
 * shishi_crypto_encrypt() and decryption via shishi_crypto_encrypt()
 * without supplying all those details again.  The functions also
 * takes care of propagating the IV between calls.
 *
 * When the application no longer need to use the context, it should
 * deallocate resources associated with it by calling
 * shishi_crypto_done().
 *
 * Return value: Return a newly allocated crypto context.
 **/
Shishi_crypto *
shishi_crypto (Shishi * handle,
	       Shishi_key * key,
	       int keyusage, int32_t etype, const char *iv, size_t ivlen)
{
  Shishi_crypto *ctx;
  int rc;

  ctx = xmalloc (sizeof (*ctx));

  rc = shishi_key (handle, &ctx->key);
  /* XXX handle rc, or rather:
     change shishi_key() to return key instead of int. */
  shishi_key_copy (ctx->key, key);

  ctx->handle = handle;
  ctx->keyusage = keyusage;
  ctx->etype = etype;
  if (iv)
    ctx->iv = xmemdup (iv, ivlen);
  else
    ctx->iv = NULL;
  ctx->ivlen = ivlen;

  return ctx;
}

/**
 * shishi_crypto_encrypt:
 * @ctx: crypto context as returned by shishi_crypto().
 * @in: input array with data to encrypt.
 * @inlen: size of input array with data to encrypt.
 * @out: output array with newly allocated encrypted data.
 * @outlen: output variable with size of newly allocated output array.
 *
 * Encrypt data, using information (e.g., key and initialization
 * vector) from context.  The IV is updated inside the context after
 * this call.
 *
 * When the application no longer need to use the context, it should
 * deallocate resources associated with it by calling
 * shishi_crypto_done().
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_crypto_encrypt (Shishi_crypto * ctx,
		       const char *in, size_t inlen,
		       char **out, size_t * outlen)
{
  char *ivout = NULL;
  size_t ivoutlen;
  int rc;

  rc = shishi_encrypt_ivupdate_etype (ctx->handle, ctx->key, ctx->keyusage,
				      ctx->etype, ctx->iv, ctx->ivlen,
				      &ivout, &ivoutlen,
				      in, inlen, out, outlen);
  if (rc == SHISHI_OK)
    {
      if (ctx->iv)
	free (ctx->iv);
      ctx->iv = ivout;
      ctx->ivlen = ivoutlen;
    }

  return rc;
}

/**
 * shishi_crypto_decrypt:
 * @ctx: crypto context as returned by shishi_crypto().
 * @in: input array with data to decrypt.
 * @inlen: size of input array with data to decrypt.
 * @out: output array with newly allocated decrypted data.
 * @outlen: output variable with size of newly allocated output array.
 *
 * Decrypt data, using information (e.g., key and initialization
 * vector) from context.  The IV is updated inside the context after
 * this call.
 *
 * When the application no longer need to use the context, it should
 * deallocate resources associated with it by calling
 * shishi_crypto_done().
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_crypto_decrypt (Shishi_crypto * ctx,
		       const char *in, size_t inlen,
		       char **out, size_t * outlen)
{
  char *ivout = NULL;
  size_t ivoutlen;
  int rc;

  rc = shishi_decrypt_ivupdate_etype (ctx->handle, ctx->key, ctx->keyusage,
				      ctx->etype, ctx->iv, ctx->ivlen,
				      &ivout, &ivoutlen,
				      in, inlen, out, outlen);
  if (rc == SHISHI_OK)
    {
      if (ctx->iv)
	free (ctx->iv);
      ctx->iv = ivout;
      ctx->ivlen = ivoutlen;
    }

  return rc;
}

/**
 * shishi_crypto_close:
 * @ctx: crypto context as returned by shishi_crypto().
 *
 * Deallocate resources associated with the crypto context.
 **/
void
shishi_crypto_close (Shishi_crypto * ctx)
{
  shishi_key_done (ctx->key);
  if (ctx->iv)
    free (ctx->iv);
  free (ctx);
}
