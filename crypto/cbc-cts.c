/* cbc-cts.c
 *
 * Cipher block chaining mode, with cipher text stealing.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2003 Simon Josefsson
 *
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "cbc-cts.h"

#include "memxor.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

void
cbc_cts_encrypt(void *ctx, void (*f)(void *ctx,
				 unsigned length, uint8_t *dst,
				 const uint8_t *src),
	    unsigned block_size, uint8_t *iv,
	    unsigned length, uint8_t *dst,
	    const uint8_t *src)
{
  unsigned olength = length;
  unsigned restbytes = (length % block_size) == 0 ?
    block_size : length % block_size;

  if (olength > block_size)
    length -= block_size;

  for ( ; length >= block_size;
	length -= block_size, src += block_size, dst += block_size)
    {
      memxor(iv, src, block_size);
      f(ctx, block_size, dst, iv);
      memcpy(iv, dst, block_size);
    }

  if (olength > block_size)
    {
      memcpy(dst, dst - block_size, restbytes);
      dst -= block_size;
      memcpy(dst, src, restbytes);
      memset(dst + restbytes, 0, block_size - restbytes);
      memxor(iv, dst, block_size);
      f(ctx, block_size, dst, iv);
    }
}

/* Reqires that dst != src */
static void
cbc_cts_decrypt_internal(void *ctx, void (*f)(void *ctx,
					  unsigned length, uint8_t *dst,
					  const uint8_t *src),
		     unsigned block_size, uint8_t *iv,
		     unsigned length, uint8_t *dst,
		     const uint8_t *src)
{
  assert(length);
  assert( !(length % block_size) );
  assert(src != dst);

  /* Decrypt in ECB mode */
  f(ctx, length, dst, src);

  /* XOR the cryptotext, shifted one block */
  memxor(dst, iv, block_size);
  memxor(dst + block_size, src, length - block_size);
  memcpy(iv, src + length - block_size, block_size);
}

/* Don't allocate any more space than this on the stack */
#define CBC_CTS_BUFFER_LIMIT 4096

void
cbc_cts_decrypt(void *ctx, void (*f)(void *ctx,
				 unsigned length, uint8_t *dst,
				 const uint8_t *src),
	    unsigned block_size, uint8_t *iv,
	    unsigned length, uint8_t *dst,
	    const uint8_t *src)
{
  assert(!(length % block_size));

  if (!length)
    return;

  if (src != dst)
    cbc_cts_decrypt_internal(ctx, f, block_size, iv,
			 length, dst, src);
  else
    {
      /* We need a copy of the ciphertext, so we can't ECB decrypt in
       * place.
       *
       * If length is small, we allocate a complete copy of src on the
       * stack. Otherwise, we allocate a block of size at most
       * CBC_CTS_BUFFER_LIMIT, and process that amount of data at a
       * time.
       *
       * NOTE: We assume that block_size <= CBC_CTS_BUFFER_LIMIT. */

      uint8_t *buffer;

      if (length <= CBC_CTS_BUFFER_LIMIT)
	buffer = alloca(length);
      else
	{
	  /* The buffer size must be an integral number of blocks. */
	  unsigned buffer_size
	    = CBC_CTS_BUFFER_LIMIT - (CBC_CTS_BUFFER_LIMIT % block_size);

	  buffer = alloca(buffer_size);

	  for ( ; length >= buffer_size;
		length -= buffer_size, dst += buffer_size, src += buffer_size)
	    {
	      memcpy(buffer, src, buffer_size);
	      cbc_cts_decrypt_internal(ctx, f, block_size, iv,
				   buffer_size, dst, buffer);
	    }
	  if (!length)
	    return;
	}
      /* Now, we have at most CBC_CTS_BUFFER_LIMIT octets left */
      memcpy(buffer, src, length);

      cbc_cts_decrypt_internal(ctx, f, block_size, iv,
			   length, dst, buffer);
    }
}
