/* encticketpart.c	encrypted ticket part handling
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

ASN1_TYPE
shishi_encticketpart (Shishi * handle)
{
  ASN1_TYPE node;
  int res;

  node = shishi_asn1_encticketpart (handle);

  res = asn1_write_value (node, "EncTicketPart.starttime", NULL, 0);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  res = asn1_write_value (node, "EncTicketPart.renew-till", NULL, 0);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  res = asn1_write_value (node, "EncTicketPart.caddr", NULL, 0);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  res = asn1_write_value (node, "EncTicketPart.authorization-data", NULL, 0);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  return node;
}

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
  res = shishi_asn1_field (handle, encticketpart, (char *) etype, &buflen,
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

  res = shishi_asn1_integer_field (handle, encticketpart, &keytype,
				    "EncTicketPart.key.keytype");
  if (res != SHISHI_OK)
    return res;

  buflen = BUFSIZ;
  res = shishi_asn1_field (handle, encticketpart, buf, &buflen,
			    "EncTicketPart.key.keyvalue");
  if (res != ASN1_SUCCESS)
    return res;

  res = shishi_key_from_value (handle, keytype, buf, key);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_encticketpart_key_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @encticketpart: input EncTicketPart variable.
 * @key: key handle with information to store in encticketpart.
 *
 * Set the EncTicketPart.key field to key type and value of supplied
 * key.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_encticketpart_key_set (Shishi * handle,
			      ASN1_TYPE encticketpart,
			      Shishi_key *key)
{
  int res;
  char buf[BUFSIZ];
  int keytype;

  keytype = shishi_key_type (key);
  sprintf(buf, "%d", keytype);
  res = asn1_write_value (encticketpart, "EncTicketPart.key.keytype", buf, 0);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  res = asn1_write_value (encticketpart, "EncTicketPart.key.keyvalue",
			  shishi_key_value (key),
			  shishi_key_length (key));
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_encticketpart_flags_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @encticketpart: input EncTicketPart variable.
 * @flags: flags to set in encticketpart.
 *
 * Set the EncTicketPart.flags to supplied value.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_encticketpart_flags_set (Shishi * handle,
				ASN1_TYPE encticketpart,
				int flags)
{
  int res;
  char buf[BUFSIZ];

  sprintf(buf, "%d", flags);
  res = asn1_write_value (encticketpart, "EncTicketPart.flags", buf, 0);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_encticketpart_crealm_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @encticketpart: input EncTicketPart variable.
 * @realm: input array with name of realm.
 *
 * Set the realm field in the KDC-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_encticketpart_crealm_set (Shishi * handle,
				 ASN1_TYPE encticketpart,
				 const char *realm)
{
  int res = ASN1_SUCCESS;

  res = asn1_write_value (encticketpart, "EncTicketPart.crealm", realm, 0);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_encticketpart_cname_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @encticketpart: input EncTicketPart variable.
 * @name_type: type of principial, see Shishi_name_type, usually
 *             SHISHI_NT_UNKNOWN.
 * @principal: input array with principal name.
 *
 * Set the client name field in the EncTicketPart.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_encticketpart_cname_set (Shishi * handle,
				ASN1_TYPE encticketpart,
				Shishi_name_type name_type,
				const char *principal)
{
  int res = ASN1_SUCCESS;
  char buf[BUFSIZ];

  sprintf (buf, "%d", name_type);

  res = asn1_write_value (encticketpart, "EncTicketPart.cname.name-type",
			  buf, 0);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return !SHISHI_OK;
    }

  res =
    asn1_write_value (encticketpart, "EncTicketPart.cname.name-string",
		      NULL, 0);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return !SHISHI_OK;
    }

  res =
    asn1_write_value (encticketpart, "EncTicketPart.cname.name-string",
		      "NEW", 1);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return !SHISHI_OK;
    }
  res = asn1_write_value (encticketpart, "EncTicketPart.cname.name-string.?1",
			  principal, strlen (principal));
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return !SHISHI_OK;
    }

  return SHISHI_OK;
}

/**
 * shishi_encticketpart_transited_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @encticketpart: input EncTicketPart variable.
 * @trtype: transitedencoding type, e.g. SHISHI_TR_DOMAIN_X500_COMPRESS.
 * @trdata: actual transited realm data.
 * @trdatalen: length of actual transited realm data.
 *
 * Set the EncTicketPart.transited field to supplied value.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_encticketpart_transited_set (Shishi * handle,
				    ASN1_TYPE encticketpart,
				    int trtype,
				    char *trdata,
				    size_t trdatalen)
{
  int res;
  char buf[BUFSIZ];

  sprintf(buf, "%d", trtype);
  res = asn1_write_value (encticketpart, "EncTicketPart.transited.tr-type",
			  buf, 0);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  res = asn1_write_value (encticketpart, "EncTicketPart.transited.contents",
			  trdata, trdatalen);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_encticketpart_authtime_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @encticketpart: input EncTicketPart variable.
 * @authtime: character buffer containing a generalized time string.
 *
 * Set the EncTicketPart.authtime to supplied value.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_encticketpart_authtime_set (Shishi * handle,
				   ASN1_TYPE encticketpart,
				   char *authtime)
{
  int res;

  res = asn1_write_value (encticketpart, "EncTicketPart.authtime",
			  authtime, GENERALIZEDTIME_TIME_LEN);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_encticketpart_endtime_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @encticketpart: input EncTicketPart variable.
 * @endtime: character buffer containing a generalized time string.
 *
 * Set the EncTicketPart.endtime to supplied value.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_encticketpart_endtime_set (Shishi * handle,
				  ASN1_TYPE encticketpart,
				  char *endtime)
{
  int res;

  res = asn1_write_value (encticketpart, "EncTicketPart.endtime",
			  endtime, GENERALIZEDTIME_TIME_LEN);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  return SHISHI_OK;
}

int
shishi_encticketpart_authtime (Shishi *handle,
			       ASN1_TYPE encticketpart,
			       char *authtime, int *authtimelen)
{
  return shishi_asn1_field (handle, encticketpart, authtime, authtimelen,
			    "EncTicketPart.authtime");
}

time_t
shishi_encticketpart_authctime (Shishi *handle, ASN1_TYPE encticketpart)
{
  char authtime[GENERALIZEDTIME_TIME_LEN + 1];
  int authtimelen;
  time_t t;
  int res;

  authtimelen = sizeof (authtime);
  res = shishi_encticketpart_authtime (handle, encticketpart,
				       authtime, &authtimelen);
  if (res != SHISHI_OK)
    return (time_t) - 1;

  authtime[GENERALIZEDTIME_TIME_LEN] = '\0';

  t = shishi_generalize_ctime (handle, authtime);

  return t;
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
