/* util.c	auxilliary help functions.
 * Copyright (C) 2002, 2003  Simon Josefsson
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
 */

#include "internal.h"

void
_shishi_escapeprint (const char *str, int len)
{
  int i;

  printf ("\t ;; `");
  for (i = 0; i < len; i++)
    if ((str[i] >= 'A' && str[i] <= 'Z') ||
	(str[i] >= 'a' && str[i] <= 'z') ||
	(str[i] >= '0' && str[i] <= '9') || str[i] == '.')
      printf ("%c", str[i] & 0xFF);
    else
      printf ("\\x%02x", str[i] & 0xFF);
  printf ("' (length %d bytes)\n", len);
}

void
_shishi_hexprint (const char *str, int len)
{
  int i;

  printf ("\t ;; ");
  for (i = 0; i < len; i++)
    {
      printf ("%02x ", str[i] & 0xFF);
      if ((i + 1) % 8 == 0)
	printf (" ");
      if ((i + 1) % 16 == 0 && i + 1 < len)
	printf ("\n\t ;; ");
    }
  puts ("");
}

void
_shishi_binprint (const char *str, int len)
{
  int i;

  printf ("\t ;; ");
  for (i = 0; i < len; i++)
    {
      printf ("%d%d%d%d%d%d%d%d ",
	      str[i] & 0x80 ? 1 : 0,
	      str[i] & 0x40 ? 1 : 0,
	      str[i] & 0x20 ? 1 : 0,
	      str[i] & 0x10 ? 1 : 0,
	      str[i] & 0x08 ? 1 : 0,
	      str[i] & 0x04 ? 1 : 0,
	      str[i] & 0x02 ? 1 : 0, str[i] & 0x01 ? 1 : 0);
      if ((i + 1) % 3 == 0)
	printf (" ");
      if ((i + 1) % 6 == 0 && i + 1 < len)
	printf ("\n\t ;; ");
    }
  puts ("");
}

void
_shishi_bin7print (const char *str, int len)
{
  int i;

  printf ("\t ;; ");
  for (i = 0; i < len; i++)
    {
      printf ("%d%d%d%d%d%d%d ",
	      str[i] & 0x40 ? 1 : 0,
	      str[i] & 0x20 ? 1 : 0,
	      str[i] & 0x10 ? 1 : 0,
	      str[i] & 0x08 ? 1 : 0,
	      str[i] & 0x04 ? 1 : 0,
	      str[i] & 0x02 ? 1 : 0, str[i] & 0x01 ? 1 : 0);
      if ((i + 1) % 3 == 0)
	printf (" ");
      if ((i + 1) % 6 == 0 && i + 1 < len)
	printf ("\n\t ;; ");
    }
  puts ("");
}

time_t
xtime (time_t * t)
{
  time_t now;

  now = time (t);
  if (now == (time_t) - 1)
    {
      perror ("time");
      abort ();
    }

  return now;
}

int
xgettimeofday (struct timeval *tv, struct timezone *tz)
{
  int rc;

  rc = gettimeofday (tv, tz);
  if (rc != 0)
    {
      perror ("gettimeofday");
      abort ();
    }

  return rc;
}
