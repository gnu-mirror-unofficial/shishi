/* crypto-ctx.c   high-level crypto functions
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

#include "internal.h"
#include "crypto.h"

struct Shishi_crypto
{
  Shishi * handle;
  Shishi_key * key;
  int keyusage;
  int32_t etype;
  char * iv;
  size_t ivlen;
};

Shishi_crypto *
shishi_crypto_init (Shishi * handle,
		    Shishi_key * key,
		    int keyusage,
		    int32_t etype,
		    const char * iv, size_t ivlen)
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
  ctx->iv = xmemdup (iv, ivlen);
  ctx->ivlen = ivlen;

  return ctx;
}

int
shishi_crypto_encrypt (Shishi_crypto * ctx,
		       const char *in, size_t inlen,
		       char **out, size_t * outlen)
{
  char *ivout;
  size_t ivoutlen;
  int rc;

  rc = shishi_encrypt_ivupdate_etype (ctx->handle, ctx->key, ctx->keyusage,
				       ctx->etype, ctx->iv, ctx->ivlen,
				       &ivout, &ivoutlen,
				       in, inlen,
				       out, outlen);
  if (rc == SHISHI_OK)
    {
      free (ctx->iv);
      ctx->iv = ivout;
      ctx->ivlen = ivoutlen;
    }

  return rc;
}

int
shishi_crypto_decrypt (Shishi_crypto * ctx,
		       const char *in, size_t inlen,
		       char **out, size_t * outlen)
{
  char *ivout;
  size_t ivoutlen;
  int rc;

  rc = shishi_decrypt_ivupdate_etype (ctx->handle, ctx->key, ctx->keyusage,
				      ctx->etype, ctx->iv, ctx->ivlen,
				      &ivout, &ivoutlen,
				      in, inlen,
				      out, outlen);
  if (rc == SHISHI_OK)
    {
      free (ctx->iv);
      ctx->iv = ivout;
      ctx->ivlen = ivoutlen;
    }

  return rc;
}

void
shishi_crypto_close (Shishi_crypto * ctx)
{
  shishi_key_done (ctx->key);
  free (ctx->iv);
  free (ctx);
}
