/* crypto-null.c --- NULL crypto functions
 * Copyright (C) 2002, 2003, 2004, 2007  Simon Josefsson
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

#include "crypto.h"

static int
null_encrypt (Shishi * handle,
	      Shishi_key * key,
	      int keyusage,
	      const char *iv, size_t ivlen,
	      char **ivout, size_t * ivoutlen,
	      const char *in, size_t inlen, char **out, size_t * outlen)
{
  *outlen = inlen;
  *out = xmalloc (*outlen);
  memcpy (*out, in, inlen);

  if (ivout)
    *ivout = NULL;
  if (ivoutlen)
    *ivoutlen = 0;

  return SHISHI_OK;
}

static int
null_decrypt (Shishi * handle,
	      Shishi_key * key,
	      int keyusage,
	      const char *iv, size_t ivlen,
	      char **ivout, size_t * ivoutlen,
	      const char *in, size_t inlen, char **out, size_t * outlen)
{
  *outlen = inlen;
  *out = xmalloc (*outlen);
  memcpy (*out, in, inlen);

  if (ivout)
    *ivout = NULL;
  if (ivoutlen)
    *ivoutlen = 0;

  return SHISHI_OK;
}

static int
null_random_to_key (Shishi * handle,
		    const char *rnd, size_t rndlen, Shishi_key * outkey)
{
  return SHISHI_OK;
}

static int
null_string_to_key (Shishi * handle,
		    const char *password, size_t passwordlen,
		    const char *salt, size_t saltlen,
		    const char *parameter, Shishi_key * outkey)
{
  return SHISHI_OK;
}

cipherinfo null_info = {
  SHISHI_NULL,
  "NULL",
  1,
  0,
  0,
  0,
  SHISHI_RSA_MD5,
  null_random_to_key,
  null_string_to_key,
  null_encrypt,
  null_decrypt
};
