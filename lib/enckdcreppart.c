/* enckdcreppart.c	Key distribution encrypted reply part functions
 * Copyright (C) 2002  Simon Josefsson
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

/**
 * shishi_enckdcreppart_get_key:
 * @handle: shishi handle as allocated by shishi_init().
 * @enckdcreppart: input EncKDCRepPart variable.
 * @keytype: output variable that holds key type.
 * @keyvalue: output array with key.
 * @keyvalue_len: on input, maximum size of output array with key,
 *                on output, holds the actual size of output array with key.
 *
 * Extract the key to use with the ticket sent in the KDC-REP
 * associated with the EndKDCRepPart input variable.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_enckdcreppart_get_key (Shishi * handle,
			      ASN1_TYPE enckdcreppart,
			      Shishi_key **key)
{
  int res;
  char buf[BUFSIZ];
  int buflen;
  int keytype;

  res = _shishi_asn1_integer_field (handle, enckdcreppart, &keytype,
				    "EncKDCRepPart.key.keytype");
  if (res != SHISHI_OK)
    return res;

  buflen = BUFSIZ;
  res = _shishi_asn1_field (handle, enckdcreppart, buf, &buflen,
			    "EncKDCRepPart.key.keyvalue");
  if (res != ASN1_SUCCESS)
    return res;

  res = shishi_key_from_value (handle, keytype, buf, key);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

int
shishi_enckdcreppart (Shishi * handle, ASN1_TYPE * enckdcreppart)
{
  int res;

  res = asn1_create_element (handle->asn1, "Kerberos5.EncKDCRepPart",
			     enckdcreppart, "EncKDCRepPart");
  if (res != ASN1_SUCCESS)
    {
      printf ("bad magic: %s\n", libtasn1_strerror (res));
      return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}
