/* gztime.c --- Convertion functions for GeneralizedTime.
 * Copyright (C) 2002-2013 Simon Josefsson
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
 * @handle: Shishi handle as allocated by shishi_init().
 * @t: C time to convert.
 *
 * Converts C time @t to a KerberosTime string representation.
 * The returned string must not be deallocated by the caller.
 *
 * Return value: Returns a KerberosTime formatted string
 *    corresponding to the input parameter.
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
 * @handle: Shishi handle as allocated by shishi_init().
 *
 * Converts the current time to a KerberosTime string.
 * The returned string must not be deallocated by the caller.
 *
 * Return value: Returns a KerberosTime formatted string
 *   corresponding to the current time.
 **/
const char *
shishi_generalize_now (Shishi * handle)
{
  time_t t = xtime (NULL);

  return shishi_generalize_time (handle, t);
}

/**
 * shishi_generalize_ctime:
 * @handle: Shishi handle as allocated by shishi_init().
 * @t: KerberosTime string to convert.
 *
 * Converts a KerberosTime formatted string in @t to
 * integral C time representation.
 *
 * Return value: Returns the C time corresponding to the input
 *   argument.
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
 * @handle: Shishi handle as allocated by shishi_init().
 * @node: ASN.1 structure to get time from.
 * @field: Name of the field in the ASN.1 node carrying time.
 * @t: Returned pointer to an allocated char array containing
 *   a null-terminated time string.
 *
 * Extracts time information from an ASN.1 structure,
 * and to be precise, does so from the named field @field
 * within the structure @node.
 *
 * Return value: Returns %SHISHI_OK if successful, or an error.
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
 * @handle: Shishi handle as allocated by shishi_init().
 * @node: ASN.1 structure to read field from.
 * @field: Name of field in @node to read.
 * @t: Pointer to a C-time valued integer, being updated with
 *   the time value to be extracted.
 *
 * Extracts time information from an ASN.1 structure @node,
 * and from an arbitrary element @field of that structure.
 *
 * Return value: Returns %SHISHI_OK if successful,
 *   %SHISHI_ASN1_NO_ELEMENT if the element does not exist,
 *   %SHISHI_ASN1_NO_VALUE if the field has no value.
 *   In all other cases, %SHISHI_ASN1_ERROR is returned.
 **/
int
shishi_ctime (Shishi * handle, Shishi_asn1 node, const char *field,
	      time_t * t)
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
