/* rijndael.c --- Shishi AES crypto self tests.
 * Copyright (C) 2002, 2003, 2004, 2007  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#include "utils.c"

#define IVLEN 16

#define KEY "chicken teriyaki"
#define IN "I would like the General Gau's Chicken, please, and wonton soup."
#define ZERO "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

static struct
{
  const char *key;
  size_t keylen;
  const char *iv;
  const char *in;
  size_t inlen;
  const char *out;
  size_t outlen;
  const char *nextiv;
} tv[] =
{
  {
  KEY, 16,
      ZERO,
      IN, 17,
      "\xc6\x35\x35\x68\xf2\xbf\x8c\xb4\xd8\xa5\x80\x36\x2d\xa7\xff\x7f\x97",
      17, "\xc6\x35\x35\x68\xf2\xbf\x8c\xb4\xd8\xa5\x80\x36\x2d\xa7\xff\x7f"},
  {
  KEY, 16,
      ZERO,
      IN, 31,
      "\xfc\x00\x78\x3e\x0e\xfd\xb2\xc1\xd4\x45\xd4\xc8\xef\xf7\xed\x22"
      "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5", 31,
      "\xfc\x00\x78\x3e\x0e\xfd\xb2\xc1\xd4\x45\xd4\xc8\xef\xf7\xed\x22"},
  {
  KEY, 16,
      ZERO,
      IN, 32,
      "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8"
      "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84",
      32, "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8"},
  {
  KEY, 16,
      ZERO,
      IN, 47,
      "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
      "\xb3\xff\xfd\x94\x0c\x16\xa1\x8c\x1b\x55\x49\xd2\xf8\x38\x02\x9e"
      "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5", 47,
      "\xb3\xff\xfd\x94\x0c\x16\xa1\x8c\x1b\x55\x49\xd2\xf8\x38\x02\x9e"},
  {
  KEY, 16,
      ZERO,
      IN, 48,
      "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
      "\x9d\xad\x8b\xbb\x96\xc4\xcd\xc0\x3b\xc1\x03\xe1\xa1\x94\xbb\xd8"
      "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8",
      48, "\x9d\xad\x8b\xbb\x96\xc4\xcd\xc0\x3b\xc1\x03\xe1\xa1\x94\xbb\xd8"},
  {
  KEY, 16,
      ZERO,
      IN, 64,
      "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
      "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8"
      "\x48\x07\xef\xe8\x36\xee\x89\xa5\x26\x73\x0d\xbc\x2f\x7b\xc8\x40"
      "\x9d\xad\x8b\xbb\x96\xc4\xcd\xc0\x3b\xc1\x03\xe1\xa1\x94\xbb\xd8",
      64, "\x48\x07\xef\xe8\x36\xee\x89\xa5\x26\x73\x0d\xbc\x2f\x7b\xc8\x40"}
};

void
test (Shishi * handle)
{
  char *out, *ivout;
  size_t i;
  int err;

  if (debug)
    shishi_cfg (handle, strdup ("verbose-crypto"));

  for (i = 0; i < sizeof (tv) / sizeof (tv[0]); i++)
    {
      err = shishi_aes_cts (handle, 0,
			    tv[i].key, tv[i].keylen,
			    tv[i].iv, &ivout, tv[i].in, tv[i].inlen, &out);

      if (debug)
	{
	  printf ("input:\n");
	  hexprint (tv[i].in, tv[i].inlen);
	  printf ("output:\n");
	  hexprint (out, tv[i].inlen);
	  if (memcmp (out, tv[i].out, tv[i].outlen) != 0)
	    {
	      printf ("expected output:\n");
	      hexprint (tv[i].out, tv[i].outlen);
	    }
	  printf ("iv out:\n");
	  hexprint (ivout, IVLEN);
	  if (memcmp (ivout, tv[i].nextiv, IVLEN) != 0)
	    {
	      printf ("expected iv out:\n");
	      hexprint (tv[i].nextiv, IVLEN);
	    }
	}

      if (err)
	fail ("shishi_aes_cts(%d) failed: %d\n", i, err);
      else
	{
	  if (memcmp (out, tv[i].out, tv[i].outlen) == 0)
	    success ("shishi_aes_cts(%d) OK\n", i);
	  else
	    fail ("shishi_aes_cts(%d) failure\n", i);

	  if (memcmp (ivout, tv[i].nextiv, IVLEN) == 0)
	    success ("shishi_aes_cts(%d) IV OK\n", i);
	  else
	    fail ("shishi_aes_cts(%d) failure IV\n", i);

	  free (out);
	  free (ivout);
	}
    }
}
