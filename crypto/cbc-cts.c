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

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "cbc-cts.h"

#include "memxor.h"

void
cbc_cts_encrypt (void *ctx,
		 void (*f) (void *ctx,
			    unsigned length,
			    uint8_t * dst,
			    const uint8_t * src),
		 unsigned block_size, uint8_t * iv,
		 unsigned length, uint8_t * dst, const uint8_t * src)
{
  unsigned nblocks = length / block_size;
  unsigned restbytes = (length % block_size) == 0 ?
    block_size : length % block_size;

  if (length > block_size)
    {
      if ((length % block_size) == 0)
	nblocks--;
    }

  for (; nblocks; nblocks--, src += block_size, dst += block_size)
    {
      memxor (iv, src, block_size);
      f (ctx, block_size, dst, iv);
      memcpy (iv, dst, block_size);
    }

  if (length > block_size)
    {
      memcpy (dst, dst - block_size, restbytes);
      dst -= block_size;
      memcpy (dst, src, restbytes);
      memset (dst + restbytes, 0, block_size - restbytes);
      memxor (iv, dst, block_size);
      f (ctx, block_size, dst, iv);
      memcpy (iv, dst + restbytes, block_size);
    }
}

void
cbc_cts_decrypt (void *ctx,
		 void (*f) (void *ctx,
			    unsigned length,
			    uint8_t * dst,
			    const uint8_t * src),
		 unsigned block_size, uint8_t * iv,
		 unsigned length, uint8_t * dst, const uint8_t * src)
{
  unsigned nblocks = length / block_size;
  unsigned restbytes = (length % block_size) == 0 ?
    block_size : length % block_size;
  uint8_t *tmpiv = alloca (block_size);

  if (length > block_size)
    {
      nblocks--;
      if ((length % block_size) == 0)
	nblocks--;
    }

  for (; nblocks; nblocks--, src += block_size, dst += block_size)
    {
      memcpy (tmpiv, src, block_size);
      f (ctx, block_size, dst, src);
      memxor (dst, iv, block_size);
      memcpy (iv, tmpiv, block_size);
    }

  if (length > block_size)
    {
      memcpy (iv, src + block_size, restbytes);
      f (ctx, block_size, dst, src);
      memxor (dst, iv, restbytes);
      memcpy (dst + block_size, dst, restbytes);
      memcpy (iv + restbytes, dst + restbytes, block_size - restbytes);
      f (ctx, block_size, dst, iv);
      memxor (dst, tmpiv, block_size);
      if ((length % block_size) == 0)
	memcpy (iv, src + block_size, block_size);
      else
	memcpy (iv, src + restbytes, block_size);
    }
}
