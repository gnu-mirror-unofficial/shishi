/* crypto-null.c	NULL crypto functions
 * Copyright (C) 2002  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with Shishi; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Note: This file is #include'd by crypto.c.
 *
 */

static int
null_encrypt (Shishi * handle,
	      int keyusage,
	      char *key,
	      int keylen,
	      char *in, 
	      int inlen, 
	      char *out,
	      int *outlen)
{
  if (*outlen < inlen)
    return !SHISHI_OK;

  memcpy (out, in, inlen);
  *outlen = inlen;

  return SHISHI_OK;
}

static int
null_decrypt (Shishi * handle,
	      int keyusage,
	      char *key,
	      int keylen,
	      char *in,
	      int inlen,
	      char *out,
	      int *outlen)
{
  if (*outlen < inlen)
    return !SHISHI_OK;

  memcpy (out, in, inlen);
  *outlen = inlen;

  return SHISHI_OK;
}

static int
null_random_to_key (Shishi * handle,
		    char *random,
		    int randomlen,
		    char *outkey)
{
  return SHISHI_OK;
}

static int
null_string_to_key_function (Shishi * handle,
			     char *password,
			     int passwordlen,
			     char *salt,
			     int saltlen,
			     char *parameter,
			     char *outkey)
{
  return SHISHI_OK;
}
