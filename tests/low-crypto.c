/* low-crypto.c --- Shishi crypto primitives self tests.
 * Copyright (C) 2002, 2003, 2004, 2006, 2007  Simon Josefsson
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

void
test (Shishi * handle)
{
  char *out, *ivout;
  int err;

  if (debug)
    shishi_cfg (handle, strdup ("verbose-crypto"));

  err = shishi_crc (handle, "abcdefgh", 8, &out);
  if (err)
    fail ("shishi_crc() failed: %d\n", err);
  else
    {
      if (memcmp (out, "\x39\xf5\xcd\xcb", 4) == 0)
	success ("shishi_crc() OK\n");
      else
	{
	  hexprint (out, 4);
	  fail ("shishi_crc() failure\n");
	}
      free (out);
    }

  err = shishi_md4 (handle, "abcdefgh", 8, &out);
  if (err)
    fail ("shishi_md4() failed: %d\n", err);
  else
    {
      if (memcmp (out, "\xad\x9d\xaf\x8d\x49\xd8\x19\x88"
		  "\x59\x0a\x6f\x0e\x74\x5d\x15\xdd", 16) == 0)
	success ("shishi_md4() OK\n");
      else
	{
	  hexprint (out, 16);
	  fail ("shishi_md4() failure\n");
	}
      free (out);
    }

  err = shishi_md5 (handle, "abcdefgh", 8, &out);
  if (err)
    fail ("shishi_md5() failed: %d\n", err);
  else
    {
      if (memcmp (out, "\xe8\xdc\x40\x81\xb1\x34\x34\xb4"
		  "\x51\x89\xa7\x20\xb7\x7b\x68\x18", 16) == 0)
	success ("shishi_md5() OK\n");
      else
	{
	  hexprint (out, 16);
	  fail ("shishi_md5() failure\n");
	}
      free (out);
    }

  err = shishi_hmac_md5 (handle, "keykeykey", 9, "abcdefgh", 8, &out);
  if (err)
    fail ("shishi_hmac_md5() failed: %d\n", err);
  else
    {
      if (memcmp (out, "\x3c\xb0\x9d\x83\x28\x01\xef\xc0"
		  "\x7b\xb3\xaf\x42\x69\xe5\x93\x9a", 16) == 0)
	success ("shishi_hmac_md5() OK\n");
      else
	{
	  hexprint (out, 16);
	  fail ("shishi_hmac_md5() failure\n");
	}
      free (out);
    }

  err = shishi_hmac_sha1 (handle, "keykeykey", 9, "abcdefgh", 8, &out);
  if (err)
    fail ("shishi_hmac_sha1() failed: %d\n", err);
  else
    {
      if (memcmp (out, "\x58\x93\x7a\x58\xfe\xea\x82\xf8"
		  "\x0e\x64\x62\x01\x40\x2b\x2c\xed\x5d\x54\xc1\xfa",
		  20) == 0)
	success ("shishi_hmac_sha1() OK\n");
      else
	{
	  hexprint (out, 20);
	  fail ("shishi_hmac_sha1() failure\n");
	}
      free (out);
    }

  err = shishi_des_cbc_mac (handle, "kdykdykd", NULL, "abcdefgh", 8, &out);
  if (err)
    fail ("shishi_des_cbc_mac() failed: %d\n", err);
  else
    {
      if (memcmp (out, "\xb9\xf1\x38\x36\x37\x7a\x6f\x4c", 8) == 0)
	success ("shishi_des_cbc_mac() OK\n");
      else
	{
	  hexprint (out, 8);
	  fail ("shishi_des_cbc_mac() failure\n");
	}
      free (out);
    }

  err = shishi_des_cbc_mac (handle, "kdykdykd", "iviviviv",
			    "abcdefgh", 8, &out);
  if (err)
    fail ("shishi_des_cbc_mac() failed: %d\n", err);
  else
    {
      if (memcmp (out, "\x7b\x66\x2d\x4d\x54\xc9\xc1\x01", 8) == 0)
	success ("shishi_des_cbc_mac() OK\n");
      else
	{
	  hexprint (out, 8);
	  fail ("shishi_des_cbc_mac() failure\n");
	}
      free (out);
    }

  err = shishi_arcfour (handle, 0, "keykeykey", 9, NULL, NULL,
			"abcdefgh", 8, &out);
  if (err)
    fail ("shishi_arcfour() failed: %d\n", err);
  else
    {
      if (memcmp (out, "\x6a\x0e\x57\x89\x41\xe9\x1c\x22", 8) == 0)
	success ("shishi_arcfour() OK\n");
      else
	{
	  hexprint (out, 8);
	  fail ("shishi_arcfour() failure\n");
	}
      free (out);
    }

  err = shishi_arcfour (handle, 0, "keykeyke", 8, NULL, &ivout,
			"abcdefghi", 9, &out);
  if (err)
    fail ("shishi_arcfour() failed: %d\n", err);
  else
    {
      if (memcmp (out, "\x17\x52\xf3\xd8\x61\x14\xe6\x76", 8) == 0)
	success ("shishi_arcfour() OK\n");
      else
	{
	  hexprint (out, 8);
	  fail ("shishi_arcfour() failure\n");
	}
      if (memcmp (ivout,
		  "\x6b\xdf\xca\xe7\x4c\xe8\x79\x53"
		  "\xd0\x4e\xe2\x37\xc9\x52\xc6\x3c"
		  "\x24\xf2\x9e\x5b\x32\x50\x07\x2e"
		  "\xee\x0f\xc2\x38\x86\x89\x4b\x21"
		  "\xd2\xc0\xa2\x7a\xb7\xae\xf1\xcb"
		  "\x03\x19\x78\x41\x9f\x74\xab\x35"
		  "\x12\x30\xe9\x04\x1c\x05\x66\x58"
		  "\x25\x62\x77\xa5\x42\x44\xd6\x6d"
		  "\x85\xc8\x43\x94\xcf\xfb\x06\x0b"
		  "\xde\x7f\x15\xa1\x8e\xaa\x70\x1b"
		  "\x98\xb0\x13\x27\x73\x4f\x2a\x3d"
		  "\x81\x29\x83\xd8\x99\x36\xd3\x54"
		  "\x4a\x31\xf0\xbe\x18\xe1\x6f\x28"
		  "\x3a\x64\x6a\x68\xef\x59\x22\xbc"
		  "\xb5\x47\x76\x63\xec\x48\x3b\x71"
		  "\x10\xc4\x87\x5f\xea\xc1\xf6\x5d"
		  "\xc5\x8b\xda\xac\xe0\xa9\x8a\xa6"
		  "\x11\x09\x0c\x72\xad\xb3\x46\xe5"
		  "\x9b\x91\x16\x93\x51\x49\xe6\xbf"
		  "\x95\xf5\xd1\x20\xe3\x90\x5a\x39"
		  "\x7b\x7e\x7c\xb9\x40\xbd\x08\x9a"
		  "\x45\xb4\xd7\x1f\x2c\x61\xb8\xcc"
		  "\xb6\x33\x92\x0e\xf9\x0a\xba\x55"
		  "\x75\x14\x5e\xb1\x26\xf8\x84\xed"
		  "\xa4\x1e\x7d\x60\xe4\xdd\x2b\xff"
		  "\xeb\xfe\xd4\x57\x8c\xa0\x88\x8d"
		  "\xdc\x00\x34\x23\xc7\xfd\x0d\x97"
		  "\x56\x96\xaf\xcd\x3f\xf7\xc3\xa7"
		  "\x6c\x65\xbb\xf3\x3e\xdb\x4d\xd9"
		  "\x1d\xa3\x9d\xf4\x17\x69\x6e\x82"
		  "\x02\xa8\x2d\x9c\xce\x1a\xb2\xfc"
		  "\xfa\x5c\x67\x2f\x8f\x01\x80\xd5" "\x09\xa2", 258) == 0)
	success ("shishi_arcfour() OK IV\n");
      else
	{
	  hexprint (ivout, 258);
	  fail ("shishi_arcfour() failure IV\n");
	}
      free (out);
      free (ivout);
    }

  err = shishi_des (handle, 0, "kdykdykd", NULL, NULL, "abcdefgh", 8, &out);
  if (err)
    fail ("shishi_des() failed: %d\n", err);
  else
    {
      if (memcmp (out, "\xb9\xf1\x38\x36\x37\x7a\x6f\x4c", 8) == 0)
	success ("shishi_des() OK\n");
      else
	{
	  hexprint (out, 8);
	  fail ("shishi_des() failure\n");
	}
      free (out);
    }

  err = shishi_des (handle, 0, "kdykdykd", "iviviviv", NULL,
		    "abcdefgh", 8, &out);
  if (err)
    fail ("shishi_des() failed: %d\n", err);
  else
    {
      if (memcmp (out, "\x7b\x66\x2d\x4d\x54\xc9\xc1\x01", 8) == 0)
	success ("shishi_des() OK\n");
      else
	{
	  hexprint (out, 8);
	  fail ("shishi_des() failure\n");
	}
      free (out);
    }

  err = shishi_des (handle, 0, "kdykdykd", "iviviviv", &ivout,
		    "abcdefgh", 8, &out);
  if (err)
    fail ("shishi_des() failed: %d\n", err);
  else
    {
      if (memcmp (out, "\x7b\x66\x2d\x4d\x54\xc9\xc1\x01", 8) == 0)
	success ("shishi_des() OK\n");
      else
	{
	  hexprint (out, 8);
	  fail ("shishi_des() failure\n");
	}

      if (memcmp (ivout, "\x7b\x66\x2d\x4d\x54\xc9\xc1\x01", 8) == 0)
	success ("shishi_des() OK IV\n");
      else
	{
	  hexprint (ivout, 8);
	  fail ("shishi_des() failure IV\n");
	}
      free (out);
      free (ivout);
    }

  err = shishi_3des (handle, 0, "kdykdykdykdykdykdykdykdy", NULL, NULL,
		     "abcdefgh", 8, &out);
  if (err)
    fail ("shishi_3des() failed: %d\n", err);
  else
    {
      if (memcmp (out, "\xd9\x4a\xd9\xa4\x92\xb1\x70\x60", 8) == 0)
	success ("shishi_3des() OK\n");
      else
	{
	  hexprint (out, 8);
	  fail ("shishi_3des() failure\n");
	}
      free (out);
    }

  err = shishi_3des (handle, 0, "kdykdykdykdykdykdykdykdy",
		     "iviviviviviviviviviviviv", NULL, "abcdefgh", 8, &out);
  if (err)
    fail ("shishi_3des() failed: %d\n", err);
  else
    {
      if (memcmp (out, "\x45\xba\x34\xb4\xda\xd7\x53\x6f", 8) == 0)
	success ("shishi_3des() OK\n");
      else
	{
	  hexprint (out, 8);
	  fail ("shishi_3des() failure\n");
	}
      free (out);
    }

  err = shishi_3des (handle, 0, "kdykdykdykdykdykdykdykdy",
		     "iviviviviviviviviviviviv", &ivout,
		     "abcdefghijklmnopqrstuvxy", 24, &out);
  if (err)
    fail ("shishi_3des() failed: %d\n", err);
  else
    {
      if (memcmp (out, "\x45\xba\x34\xb4\xda\xd7\x53\x6f"
		  "\x4e\x4b\xe8\x14\x44\x25\xf2\x19"
		  "\x46\x57\x6b\x16\xd9\x5d\xf2\x38", 24) == 0)
	success ("shishi_3des() OK\n");
      else
	{
	  hexprint (out, 24);
	  fail ("shishi_3des() failure\n");
	}

      if (memcmp (ivout, "\x46\x57\x6b\x16\xd9\x5d\xf2\x38", 8) == 0)
	success ("shishi_3des() OK IV\n");
      else
	{
	  hexprint (ivout, 8);
	  fail ("shishi_3des() failure IV\n");
	}
      free (out);
      free (ivout);
    }

  err = shishi_aes_cts (handle, 0, "keykeykeykeykeyk", 16,
			"iviviviviviviviv", &ivout,
			"abcdefghijklmnop", 16, &out);
  if (err)
    fail ("shishi_aes_cts(16) failed: %d\n", err);
  else
    {
      if (memcmp (out, "\x89\xee\x53\x33\x54\xa8\xb0\xb7"
		  "\xb6\x36\xbf\x80\xb0\xba\x6a\x4a", 16) == 0)
	success ("shishi_aes_cts(16) OK\n");
      else
	{
	  hexprint (out, 16);
	  fail ("shishi_aes_cts(16) failure\n");
	}

      if (memcmp (ivout, "\x89\xee\x53\x33\x54\xa8\xb0\xb7"
		  "\xb6\x36\xbf\x80\xb0\xba\x6a\x4a", 16) == 0)
	success ("shishi_aes_cts(16) OK IV\n");
      else
	{
	  hexprint (ivout, 16);
	  fail ("shishi_aes_cts(16) failure IV\n");
	}
      free (out);
      free (ivout);
    }

  err = shishi_aes_cts (handle, 0, "keykeykeykeykeyk", 16,
			"iviviviviviviviv", &ivout,
			"abcdefghijklmnopqrstuvxy", 24, &out);
  if (err)
    fail ("shishi_aes_cts(24) failed: %d\n", err);
  else
    {
      if (memcmp (out, "\x22\x8f\x1a\xc5\xd4\x74\xd2\x74"
		  "\x96\x4d\x2d\xcd\x0b\xa3\x0d\x8f"
		  "\x89\xee\x53\x33\x54\xa8\xb0\xb7", 24) == 0)
	success ("shishi_aes_cts(24) OK\n");
      else
	{
	  hexprint (out, 24);
	  fail ("shishi_aes_cts(24) failure\n");
	}

      if (memcmp (ivout, "\x22\x8f\x1a\xc5\xd4\x74\xd2\x74"
		  "\x96\x4d\x2d\xcd\x0b\xa3\x0d\x8f", 16) == 0)
	success ("shishi_aes_cts(24) OK IV\n");
      else
	{
	  hexprint (ivout, 16);
	  fail ("shishi_aes_cts(24) failure IV\n");
	}
      free (out);
      free (ivout);
    }

  err = shishi_aes_cts (handle, 0, "keykeykeykeykeyk", 16,
			"iviviviviviviviv", &ivout,
			"abcdefghijklmnopqrstuvx", 23, &out);
  if (err)
    fail ("shishi_aes_cts(23) failed: %d\n", err);
  else
    {
      if (memcmp (out, "\x45\x23\x5a\x0c\x6b\x8a\x0c\xad"
		  "\xe6\x50\xff\xe1\x08\x17\x9a\x6d"
		  "\x89\xee\x53\x33\x54\xa8\xb0", 23) == 0)
	success ("shishi_aes_cts(23) OK\n");
      else
	{
	  hexprint (out, 23);
	  fail ("shishi_aes_cts(23) failure\n");
	}

      if (memcmp (ivout, "\x45\x23\x5a\x0c\x6b\x8a\x0c\xad"
		  "\xe6\x50\xff\xe1\x08\x17\x9a\x6d", 16) == 0)
	success ("shishi_aes_cts(23) OK IV\n");
      else
	{
	  hexprint (ivout, 16);
	  fail ("shishi_aes_cts(23) failure IV\n");
	}
      free (out);
      free (ivout);
    }

  err = shishi_aes_cts (handle, 0, "keykeykeykeykeyk", 16,
			"iviviviviviviviv", &ivout,
			"abcdefghijklmnopqrstuvxyz", 25, &out);
  if (err)
    fail ("shishi_aes_cts(25) failed: %d\n", err);
  else
    {
      if (memcmp (out, "\xa9\x50\xdd\xcb\xa8\x5b\x5c\xb6"
		  "\x84\x7d\x38\x65\x4a\xc1\x63\xd7"
		  "\x89\xee\x53\x33\x54\xa8\xb0\xb7\xb6", 25) == 0)
	success ("shishi_aes_cts(25) OK\n");
      else
	{
	  hexprint (out, 25);
	  fail ("shishi_aes_cts(25) failure\n");
	}

      if (memcmp (ivout, "\xa9\x50\xdd\xcb\xa8\x5b\x5c\xb6"
		  "\x84\x7d\x38\x65\x4a\xc1\x63\xd7", 16) == 0)
	success ("shishi_aes_cts(25) OK IV\n");
      else
	{
	  hexprint (ivout, 16);
	  fail ("shishi_aes_cts(25) failure IV\n");
	}
      free (out);
      free (ivout);
    }
}
