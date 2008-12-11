/* gztime.c --- Convertion functions for GeneralizedTime.
 * Copyright (C) 2002, 2003, 2004, 2006, 2007, 2008  Simon Josefsson
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

/* Get xtime. */
#include "utils.h"

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
 * shishi_time:
 * @handle: shishi handle as allocated by shishi_init().
 * @node: ASN.1 node to get time from.
 * @field: Name of field in ASN.1 node to get time from.
 * @t: newly allocated output array with zero terminated time string.
 *
 * Extract time from ASN.1 structure.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_time (Shishi * handle, Shishi_asn1 node, const char *field, char **t)
{
  size_t len;
  int res;

  len = SHISHI_GENERALIZEDTIME_LENGTH + 1;
  *t = xmalloc (len);

  res = shishi_asn1_read_inline (handle, node, field, *t, &len);
  if (res != SHISHI_OK)
    return res;

  if (len <= SHISHI_GENERALIZEDTIME_LENGTH)
    {
      shishi_error_printf (handle, "Read time too short (%s)", *t);
      return SHISHI_ASN1_ERROR;
    }

  (*t)[SHISHI_GENERALIZEDTIME_LENGTH] = '\0';

  return SHISHI_OK;
}

/**
 * shishi_ctime:
 * @handle: shishi handle as allocated by shishi_init().
 * @node: ASN.1 variable to read field from.
 * @field: name of field in @node to read.
 * @t: pointer to time field to set.
 *
 * Extract time from ASN.1 structure.
 *
 * Return value: Returns SHISHI_OK if successful,
 *   SHISHI_ASN1_NO_ELEMENT if the element do not exist,
 *   SHISHI_ASN1_NO_VALUE if the field has no value, ot
 *   SHISHI_ASN1_ERROR otherwise.
 **/
int
shishi_ctime (Shishi * handle, Shishi_asn1 node, const char *field, time_t *t)
{
  char str[SHISHI_GENERALIZEDTIME_LENGTH + 1];
  size_t len = sizeof (str);
  int rc;

  rc = shishi_asn1_read_inline (handle, node, field, str, &len);
  if (rc != SHISHI_OK)
    return rc;

  *t = shishi_generalize_ctime (handle, str);

  return SHISHI_OK;
}
