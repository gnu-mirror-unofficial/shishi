/* md4.c
 *
 * The MD4 hash function, described in RFC 1320.
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

/* Based on md5.c in nettle, but hacked by Simon Josefsson to compute
 * md4 checksums using a public domain md4 implementation with the
 * following comments:
 *
 * Modified by Wei Dai from Andrew M. Kuchling's md4.c
 * The original code and all modifications are in the public domain.
 *
 * This is the original introductory comment:
 *
 *  md4.c : MD4 hash algorithm.
 *
 * Part of the Python Cryptography Toolkit, version 1.1
 *
 * Distribute and use freely; there are no restrictions on further
 * dissemination and usage except those imposed by the laws of your
 * country of residence.
 */

#include "md4.h"

#include "macros.h"

#include <assert.h>
#include <string.h>

/* A block, treated as a sequence of 32-bit words. */
#define MD4_DATA_LENGTH 16

static void
md4_transform(uint32_t *digest, const uint32_t *data);

static void
md4_block(struct md4_ctx *ctx, const uint8_t *block);

void
md4_init(struct md4_ctx *ctx)
{
  ctx->digest[0] = 0x67452301;
  ctx->digest[1] = 0xefcdab89;
  ctx->digest[2] = 0x98badcfe;
  ctx->digest[3] = 0x10325476;
  
  ctx->count_l = ctx->count_h = 0;
  ctx->index = 0;
}

void
md4_update(struct md4_ctx *ctx,
	   unsigned length,
	   const uint8_t *data)
{
  if (ctx->index)
    {
      /* Try to fill partial block */
      unsigned left = MD4_DATA_SIZE - ctx->index;
      if (length < left)
	{
	  memcpy(ctx->block + ctx->index, data, length);
	  ctx->index += length;
	  return; /* Finished */
	}
      else
	{
	  memcpy(ctx->block + ctx->index, data, left);
	  md4_block(ctx, ctx->block);
	  data += left;
	  length -= left;
	}
    }
  while (length >= MD4_DATA_SIZE)
    {
      md4_block(ctx, data);
      data += MD4_DATA_SIZE;
      length -= MD4_DATA_SIZE;
    }
  if ((ctx->index = length))     /* This assignment is intended */
    /* Buffer leftovers */
    memcpy(ctx->block, data, length);
}

/* Final wrapup - pad to MD4_DATA_SIZE-byte boundary with the bit
 * pattern 1 0* (64-bit count of bits processed, LSB-first) */

static void
md4_final(struct md4_ctx *ctx)
{
  uint32_t data[MD4_DATA_LENGTH];
  unsigned i;
  unsigned words;
  
  i = ctx->index;

  /* Set the first char of padding to 0x80. This is safe since there
   * is always at least one byte free */
  assert(i < MD4_DATA_SIZE);
  ctx->block[i++] = 0x80;

  /* Fill rest of word */
  for( ; i & 3; i++)
    ctx->block[i] = 0;

  /* i is now a multiple of the word size 4 */
  words = i >> 2;
  for (i = 0; i < words; i++)
    data[i] = LE_READ_UINT32(ctx->block + 4*i);
  
  if (words > (MD4_DATA_LENGTH-2))
    { /* No room for length in this block. Process it and
       * pad with another one */
      for (i = words ; i < MD4_DATA_LENGTH; i++)
	data[i] = 0;
      md4_transform(ctx->digest, data);
      for (i = 0; i < (MD4_DATA_LENGTH-2); i++)
	data[i] = 0;
    }
  else
    for (i = words ; i < MD4_DATA_LENGTH - 2; i++)
      data[i] = 0;
  
  /* There are 512 = 2^9 bits in one block 
   * Little-endian order => Least significant word first */

  data[MD4_DATA_LENGTH-1] = (ctx->count_h << 9) | (ctx->count_l >> 23);
  data[MD4_DATA_LENGTH-2] = (ctx->count_l << 9) | (ctx->index << 3);
  md4_transform(ctx->digest, data);
}

void
md4_digest(struct md4_ctx *ctx,
	   unsigned length,
	   uint8_t *digest)
{
  unsigned i;
  unsigned words;
  unsigned leftover;
  
  assert(length <= MD4_DIGEST_SIZE);

  md4_final(ctx);
  
  words = length / 4;
  leftover = length % 4;
  
  /* Little endian order */
  for (i = 0; i < words; i++, digest += 4)
    LE_WRITE_UINT32(digest, ctx->digest[i]);

  if (leftover)
    {
      uint32_t word;
      unsigned j;

      assert(i < _MD4_DIGEST_LENGTH);
      
      /* Still least significant byte first. */
      for (word = ctx->digest[i], j = 0; j < leftover;
	   j++, word >>= 8)
	digest[j] = word & 0xff;
    }
  md4_init(ctx);
}

#if defined(__GNUC__) && defined(__i386__)
static inline uint32_t
rol( uint32_t x, int n)
{
  __asm__("roll %%cl,%0"
	  :"=r" (x)
	  :"0" (x),"c" (n));
  return x;
}
#else
#define rol(x,n) ( ((x) << (n)) | ((x) >> (32-(n))) )
#endif

/* MD4 functions */
#define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

/* Perform the MD4 transformation on one full block of 16 32-bit
 * words.
 *
 * Compresses 20 (_MD4_DIGEST_LENGTH + MD4_DATA_LENGTH) words into 4
 * (_MD4_DIGEST_LENGTH) words. */

static void
md4_transform(uint32_t *digest, const uint32_t *data)
{
  uint32_t A, B, C, D;
  A = digest[0];
  B = digest[1];
  C = digest[2];
  D = digest[3];

  /* Round 1.  */
#define function(a,b,c,d,k,s) a=rol(a+F(b,c,d)+data[k],s);
  function(A,B,C,D, 0, 3);
  function(D,A,B,C, 1, 7);
  function(C,D,A,B, 2,11);
  function(B,C,D,A, 3,19);
  function(A,B,C,D, 4, 3);
  function(D,A,B,C, 5, 7);
  function(C,D,A,B, 6,11);
  function(B,C,D,A, 7,19);
  function(A,B,C,D, 8, 3);
  function(D,A,B,C, 9, 7);
  function(C,D,A,B,10,11);
  function(B,C,D,A,11,19);
  function(A,B,C,D,12, 3);
  function(D,A,B,C,13, 7);
  function(C,D,A,B,14,11);
  function(B,C,D,A,15,19);

#undef function

  /* Round 2.  */
#define function(a,b,c,d,k,s) a=rol(a+G(b,c,d)+data[k]+0x5a827999,s);

  function(A,B,C,D, 0, 3);
  function(D,A,B,C, 4, 5);
  function(C,D,A,B, 8, 9);
  function(B,C,D,A,12,13);
  function(A,B,C,D, 1, 3);
  function(D,A,B,C, 5, 5);
  function(C,D,A,B, 9, 9);
  function(B,C,D,A,13,13);
  function(A,B,C,D, 2, 3);
  function(D,A,B,C, 6, 5);
  function(C,D,A,B,10, 9);
  function(B,C,D,A,14,13);
  function(A,B,C,D, 3, 3);
  function(D,A,B,C, 7, 5);
  function(C,D,A,B,11, 9);
  function(B,C,D,A,15,13);

#undef function

  /* Round 3.  */
#define function(a,b,c,d,k,s) a=rol(a+H(b,c,d)+data[k]+0x6ed9eba1,s);

  function(A,B,C,D, 0, 3);
  function(D,A,B,C, 8, 9);
  function(C,D,A,B, 4,11);
  function(B,C,D,A,12,15);
  function(A,B,C,D, 2, 3);
  function(D,A,B,C,10, 9);
  function(C,D,A,B, 6,11);
  function(B,C,D,A,14,15);
  function(A,B,C,D, 1, 3);
  function(D,A,B,C, 9, 9);
  function(C,D,A,B, 5,11);
  function(B,C,D,A,13,15);
  function(A,B,C,D, 3, 3);
  function(D,A,B,C,11, 9);
  function(C,D,A,B, 7,11);
  function(B,C,D,A,15,15);

  digest[0] += A;
  digest[1] += B;
  digest[2] += C;
  digest[3] += D;
}

static void
md4_block(struct md4_ctx *ctx, const uint8_t *block)
{
  uint32_t data[MD4_DATA_LENGTH];
  unsigned i;
  
  /* Update block count */
  if (!++ctx->count_l)
    ++ctx->count_h;

  /* Endian independent conversion */
  for (i = 0; i<16; i++, block += 4)
    data[i] = LE_READ_UINT32(block);

  md4_transform(ctx->digest, data);
}
