/* encticketpart.c	encrypted ticket part handling
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

#include "internal.h"

/**
 * shishi_asn1ticket_get_enc_part_etype:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcrep: Ticket variable to get value from.
 * @etype: output variable that holds the value.
 * 
 * Extract Ticket.enc-part.etype.
 * 
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_encticketpart_get_enc_part_etype (Shishi * handle,
					 ASN1_TYPE encticketpart, int *etype)
{
  int buflen;
  int res;

  *etype = 0;
  buflen = sizeof (*etype);
  res = _shishi_asn1_field (handle, encticketpart, (char *) etype, &buflen,
			    "EncTicketPart.enc-part.etype");

  return res;
}

/**
 * shishi_encticketpart_get_key:
 * @handle: shishi handle as allocated by shishi_init().
 * @encticketpart: input EncTicketPart variable.
 * @keytype: output variable that holds key type.
 * @keyvalue: output array with key.
 * @keyvalue_len: on input, maximum size of output array with key,
 *                on output, holds the actual size of output array with key.
 * 
 * Extract the session key in the Ticket.
 * 
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_encticketpart_get_key (Shishi * handle,
			      ASN1_TYPE encticketpart,
			      Shishi_key **key)
{
  int res;
  char buf[BUFSIZ];
  int buflen;
  int keytype;

  res = _shishi_asn1_integer_field (handle, encticketpart, &keytype,
				    "EncTicketPart.key.keytype");
  if (res != SHISHI_OK)
    return res;

  buflen = BUFSIZ;
  res = _shishi_asn1_field (handle, encticketpart, buf, &buflen,
			    "EncTicketPart.key.keyvalue");
  if (res != ASN1_SUCCESS)
    return res;

  *key = shishi_key (keytype, buf);

  return SHISHI_OK;
}

int
shishi_encticketpart_cname_get (Shishi * handle,
				ASN1_TYPE encticketpart,
				char *cname, int *cnamelen)
{
  return shishi_principal_name_get (handle, encticketpart,
				    "EncTicketPart.cname", cname, cnamelen);
}

int
shishi_encticketpart_cnamerealm_get (Shishi * handle,
				     ASN1_TYPE encticketpart,
				     char *cnamerealm, int *cnamerealmlen)
{
  return shishi_principal_name_realm_get (handle, encticketpart,
					  "EncTicketPart.cname",
					  encticketpart,
					  "EncTicketPart.crealm",
					  cnamerealm, cnamerealmlen);
}
