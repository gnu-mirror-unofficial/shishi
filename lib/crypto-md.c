/* crypto-md.c	DES crypto functions
 * Copyright (C) 2002, 2003  Simon Josefsson
 * Copyright (C) 2003  Nicolas Pouvesle
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
 * Note: This file is #include'd by crypto.c.
 *
 */

static int
md4_checksum (Shishi * handle,
	      Shishi_key * key,
	      int keyusage,
	      int cksumtype,
	      const char *in, size_t inlen, char **out, size_t * outlen)
{
  if (outlen)
    *outlen = 16;
  return shishi_md4 (handle, in, inlen, out);
}

static int
md5_checksum (Shishi * handle,
	      Shishi_key * key,
	      int keyusage,
	      int cksumtype,
	      const char *in, size_t inlen, char **out, size_t * outlen)
{
  if (outlen)
    *outlen = 16;
  return shishi_md5 (handle, in, inlen, out);
}
