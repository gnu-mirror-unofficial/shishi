/* gztime.c	convert into GeneralizedTime
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
#include "timegm.h"

const char *
shishi_generalize_time (Shishi * handle, time_t t)
{
  struct tm *tm;

  tm = gmtime (&t);
  strftime (handle->gztime_buf, sizeof (handle->gztime_buf),
	    "%Y%m%d%H%M%SZ", tm);

  return handle->gztime_buf;
}

const char *
shishi_generalize_now (Shishi * handle)
{
  time_t t = xtime (NULL);

  return shishi_generalize_time (handle, t);
}

time_t
shishi_generalize_ctime (Shishi * handle, const char *t)
{
  struct tm tm;
  time_t ct;

  memset (&tm, 0, sizeof (tm));

  sscanf (t, "%4u%2u%2u%2u%2u%2uZ",
	  &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
	  &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
  tm.tm_year -= 1900;
  tm.tm_mon--;

  ct = timegm (&tm);

  return ct;
}
