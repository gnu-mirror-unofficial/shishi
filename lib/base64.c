/* base64.c	base64 encoding and decoding functions
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
 */

/* 
 * This code is heavily modified from fetchmail (also GPL'd, of
 * course) by Brendan Cully <brendan@kublai.com>, via Mutt.
 * 
 * Original copyright notice:
 * 
 * The code in the fetchmail distribution is Copyright 1997 by Eric
 * S. Raymond.  Portions are also copyrighted by Carl Harris, 1993
 * and 1995.  Copyright retained for the purpose of protecting free
 * redistribution of source. 
 * 
 */

#include <string.h>
#include <ctype.h>

char B64Chars[64] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
  'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
  'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
  't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', '+', '/'
};

#define BAD     -1

static const char base64val[] = {
  BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD,
  BAD,
  BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD,
  BAD,
  BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, 62, BAD, BAD, BAD,
  63,
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, BAD, BAD, BAD, BAD, BAD, BAD,
  BAD, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, BAD, BAD, BAD, BAD, BAD,
  BAD, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, BAD, BAD, BAD, BAD, BAD
};

#define base64val(c) B64Chars[(unsigned int)(c)]

#define DECODE64(c)  (isascii(c) ? base64val[c] : BAD)

/* raw bytes to null-terminated base 64 string */
void
shishi_to_base64 (unsigned char *out, const unsigned char *in, size_t len,
		  size_t olen)
{
  while (len >= 3 && olen > 10)
    {
      *out++ = B64Chars[in[0] >> 2];
      *out++ = B64Chars[((in[0] << 4) & 0x30) | (in[1] >> 4)];
      *out++ = B64Chars[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
      *out++ = B64Chars[in[2] & 0x3f];
      olen -= 4;
      len -= 3;
      in += 3;
    }

  /* clean up remainder */
  if (len > 0 && olen > 4)
    {
      unsigned char fragment;

      *out++ = B64Chars[in[0] >> 2];
      fragment = (in[0] << 4) & 0x30;
      if (len > 1)
	fragment |= in[1] >> 4;
      *out++ = B64Chars[fragment];
      *out++ = (len < 2) ? '=' : B64Chars[(in[1] << 2) & 0x3c];
      *out++ = '=';
    }
  *out = '\0';
}

/* Convert '\0'-terminated base 64 string to raw bytes.
 * Returns length of returned buffer, or -1 on error */
int
shishi_from_base64 (unsigned char *out, const unsigned char *in)
{
  int len = 0;
  register unsigned char digit1, digit2, digit3, digit4;

  do
    {
      digit1 = in[0];
      if (digit1 > 127 || DECODE64 (digit1) == BAD)
	return -1;
      digit2 = in[1];
      if (digit2 > 127 || DECODE64 (digit2) == BAD)
	return -1;
      digit3 = in[2];
      if (digit3 > 127 || ((digit3 != '=') && (DECODE64 (digit3) == BAD)))
	return -1;
      digit4 = in[3];
      if (digit4 > 127 || ((digit4 != '=') && (DECODE64 (digit4) == BAD)))
	return -1;
      in += 4;

      /* digits are already sanity-checked */
      *out++ = (DECODE64 (digit1) << 2) | (DECODE64 (digit2) >> 4);
      len++;
      if (digit3 != '=')
	{
	  *out++ =
	    ((DECODE64 (digit2) << 4) & 0xf0) | (DECODE64 (digit3) >> 2);
	  len++;
	  if (digit4 != '=')
	    {
	      *out++ = ((DECODE64 (digit3) << 6) & 0xc0) | DECODE64 (digit4);
	      len++;
	    }
	}
    }
  while (*in && digit4 != '=');

  return len;
}
