/* cbc-cts.h
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

#ifndef NETTLE_CBC_CTS_H_INCLUDED
#define NETTLE_CBC_CTS_H_INCLUDED

#include "cbc.h"

void
cbc_cts_encrypt(void *ctx, void (*f)(void *ctx,
				     unsigned length, uint8_t *dst,
				     const uint8_t *src),
		unsigned block_size, uint8_t *iv,
		unsigned length, uint8_t *dst,
		const uint8_t *src);

void
cbc_cts_decrypt(void *ctx, void (*f)(void *ctx,
				     unsigned length, uint8_t *dst,
				     const uint8_t *src),
		unsigned block_size, uint8_t *iv,
		unsigned length, uint8_t *dst,
		const uint8_t *src);

#define CBC_CTS_CTX(type, size) CBC_CTX(type, size)

#define CBC_CTS_SET_IV(ctx, data) CBC_SET_IV(ctx, data)

#define CBC_CTS_ENCRYPT(self, f, length, dst, src)			\
  (0 ? ((f)(&(self)->ctx, 0, NULL, NULL))				\
   : cbc_cts_encrypt((void *) &(self)->ctx,				\
		     (void (*)(void *, unsigned,			\
			       uint8_t *, const uint8_t *)) (f),	\
		     sizeof((self)->iv), (self)->iv,			\
		     (length), (dst), (src)))

#define CBC_CTS_DECRYPT(self, f, length, dst, src)			\
  (0 ? ((f)(&(self)->ctx, 0, NULL, NULL))				\
   : cbc_cts_decrypt((void *) &(self)->ctx,				\
		     (void (*)(void *, unsigned,			\
			       uint8_t *, const uint8_t *)) (f),	\
		     sizeof((self)->iv), (self)->iv,			\
		     (length), (dst), (src)))

#endif /* NETTLE_CBC_CTS_H_INCLUDED */
