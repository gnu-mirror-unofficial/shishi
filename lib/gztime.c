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

/**
 * shishi_generalize_time:
 * @handle: shishi handle as allocated by shishi_init().
 * @t: C time to convert.
 *
 * Convert C time to KerberosTime.  The string must not be deallocate
 * by caller.
 *
 * Return value: Return a KerberosTime time string corresponding to C time t.
 **/
const char *
shishi_generalize_time (Shishi * handle, time_t t)
{
  struct tm *tm;

  tm = gmtime (&t);
  strftime (handle->gztime_buf, sizeof (handle->gztime_buf),
	    "%Y%m%d%H%M%SZ", tm);

  return handle->gztime_buf;
}

/**
 * shishi_generalize_now:
 * @handle: shishi handle as allocated by shishi_init().
 *
 * Convert current time to KerberosTime.  The string must not be
 * deallocate by caller.
 *
 * Return value: Return a KerberosTime time string corresponding to
 *   current time.
 **/
const char *
shishi_generalize_now (Shishi * handle)
{
  time_t t = xtime (NULL);

  return shishi_generalize_time (handle, t);
}

/**
 * shishi_generalize_ctime:
 * @handle: shishi handle as allocated by shishi_init().
 * @t: KerberosTime to convert.
 *
 * Convert KerberosTime to C time.
 *
 * Return value: Returns C time corresponding to KerberosTime t.
 **/
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

/**
 * shishi_time_get:
 * @handle: shishi handle as allocated by shishi_init().
 * @node: ASN.1 node to get time from.
 * @field: Name of field in ASN.1 node to get time from.
 * @time: newly allocated output array with zero terminated time string.
 *
 * Extract time from ASN.1 structure.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_time (Shishi * handle, Shishi_asn1 node,
	     const char *field, char **time)
{
  size_t len;
  int res;

  len = GENERALIZEDTIME_TIME_LEN + 1;
  *time = xmalloc (len);

  res = shishi_asn1_read (handle, node, field, *time, &len);
  if (res != SHISHI_OK)
    return res;

  if (len <= GENERALIZEDTIME_TIME_LEN)
    {
      shishi_error_printf (handle, "Read time too short (%s)", *time);
      return SHISHI_ASN1_ERROR;
    }

  (*time)[GENERALIZEDTIME_TIME_LEN] = '\0';

  return SHISHI_OK;
}
