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
