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

Shishi_asn1
shishi_encticketpart (Shishi * handle)
{
  Shishi_asn1 node;
  int res;

  node = shishi_asn1_encticketpart (handle);

  res = shishi_asn1_write (handle, node, "starttime", NULL, 0);
  if (res != SHISHI_OK)
    {
      shishi_asn1_done (handle, node);
      return NULL;
    }

  res = shishi_asn1_write (handle, node, "renew-till", NULL, 0);
  if (res != SHISHI_OK)
    {
      shishi_asn1_done (handle, node);
      return NULL;
    }

  res = shishi_asn1_write (handle, node, "caddr", NULL, 0);
  if (res != SHISHI_OK)
    {
      shishi_asn1_done (handle, node);
      return NULL;
    }

  res = shishi_asn1_write (handle, node, "authorization-data", NULL, 0);
  if (res != SHISHI_OK)
    {
      shishi_asn1_done (handle, node);
      return NULL;
    }

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
					 Shishi_asn1 encticketpart,
					 int32_t * etype)
{
  int res;

  res = shishi_asn1_read_int32 (handle, encticketpart,
				"enc-part.etype", etype);

  return res;
}

/**
 * shishi_encticketpart_get_key:
 * @handle: shishi handle as allocated by shishi_init().
 * @encticketpart: input EncTicketPart variable.
 * @key: newly allocated key.
 *
 * Extract the session key in the Ticket.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_encticketpart_get_key (Shishi * handle,
			      Shishi_asn1 encticketpart, Shishi_key ** key)
{
  int res;
  char *buf;
  size_t buflen;
  int32_t keytype;

  res = shishi_asn1_read_int32 (handle, encticketpart,
				"key.keytype", &keytype);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_read2 (handle, encticketpart, "key.keyvalue",
			   &buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_key_from_value (handle, keytype, buf, key);
  free (buf);
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
			      Shishi_asn1 encticketpart, Shishi_key * key)
{
  int res;
  int keytype;

  keytype = shishi_key_type (key);
  res = shishi_asn1_write_uint32 (handle, encticketpart,
				  "key.keytype", keytype);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, encticketpart, "key.keyvalue",
			   shishi_key_value (key), shishi_key_length (key));
  if (res != SHISHI_OK)
    return res;

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
				Shishi_asn1 encticketpart, int flags)
{
  int res;

  res = shishi_asn1_write_uint32 (handle, encticketpart, "flags", flags);
  if (res != SHISHI_OK)
    return res;

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
				 Shishi_asn1 encticketpart, const char *realm)
{
  int res;

  res = shishi_asn1_write (handle, encticketpart, "crealm", realm, 0);
  if (res != SHISHI_OK)
    return res;

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
				Shishi_asn1 encticketpart,
				Shishi_name_type name_type,
				const char *principal)
{
  int res;

  res = shishi_asn1_write_uint32 (handle, encticketpart,
				  "cname.name-type", name_type);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, encticketpart,
			   "cname.name-string", NULL, 0);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, encticketpart,
			   "cname.name-string", "NEW", 1);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, encticketpart,
			   "cname.name-string.?1",
			   principal, strlen (principal));
  if (res != SHISHI_OK)
    return res;

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
				    Shishi_asn1 encticketpart,
				    int trtype,
				    char *trdata, size_t trdatalen)
{
  int res;

  res = shishi_asn1_write_uint32 (handle, encticketpart,
				  "transited.tr-type", trtype);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, encticketpart,
			   "transited.contents", trdata, trdatalen);
  if (res != SHISHI_OK)
    return res;

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
				   Shishi_asn1 encticketpart,
				   const char *authtime)
{
  int res;

  res = shishi_asn1_write (handle, encticketpart, "authtime",
			   authtime, GENERALIZEDTIME_TIME_LEN);
  if (res != SHISHI_OK)
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
				  Shishi_asn1 encticketpart,
				  const char *endtime)
{
  int res;

  res = shishi_asn1_write (handle, encticketpart, "endtime",
			   endtime, GENERALIZEDTIME_TIME_LEN);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

int
shishi_encticketpart_authtime (Shishi * handle,
			       Shishi_asn1 encticketpart,
			       char *authtime, size_t *authtimelen)
{
  return shishi_asn1_read (handle, encticketpart, "authtime",
			   authtime, authtimelen);
}

time_t
shishi_encticketpart_authctime (Shishi * handle, Shishi_asn1 encticketpart)
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
				Shishi_asn1 encticketpart,
				char *cname, size_t *cnamelen)
{
  return shishi_principal_name_get (handle, encticketpart,
				    "cname", cname, cnamelen);
}

int
shishi_encticketpart_cnamerealm_get (Shishi * handle,
				     Shishi_asn1 encticketpart,
				     char *cnamerealm, size_t *cnamerealmlen)
{
  return shishi_principal_name_realm_get (handle, encticketpart,
					  "cname",
					  encticketpart,
					  "crealm",
					  cnamerealm, cnamerealmlen);
}
