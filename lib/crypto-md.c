/* crypto-md.c --- DES crypto functions
 * Copyright (C) 2002, 2003, 2004, 2007, 2008  Simon Josefsson
 * Copyright (C) 2003  Free Software Foundation, Inc.
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

checksuminfo md4_info = {
  SHISHI_RSA_MD4,
  "rsa-md4",
  16,
  md4_checksum,
  NULL
};

checksuminfo md5_info = {
  SHISHI_RSA_MD5,
  "rsa-md5",
  16,
  md5_checksum,
  NULL
};
