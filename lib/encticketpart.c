/* encticketpart.c --- Encrypted ticket part handling.
 * Copyright (C) 2002, 2003, 2004, 2007  Simon Josefsson
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

  res = shishi_encticketpart_flags_set (handle, node, 0);
  if (res != SHISHI_OK)
    {
      shishi_asn1_done (handle, node);
      return NULL;
    }

  return node;
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

  res = shishi_asn1_read (handle, encticketpart, "key.keyvalue",
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

  res = shishi_asn1_write_bitstring (handle, encticketpart, "flags", flags);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

int
shishi_encticketpart_crealm (Shishi * handle,
			     Shishi_asn1 encticketpart,
			     char **crealm, size_t * crealmlen)
{
  return shishi_asn1_read (handle, encticketpart, "crealm",
			   crealm, crealmlen);
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
				    int32_t trtype,
				    const char *trdata, size_t trdatalen)
{
  int res;

  res = shishi_asn1_write_int32 (handle, encticketpart,
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
			   authtime, SHISHI_GENERALIZEDTIME_LENGTH);
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
			   endtime, SHISHI_GENERALIZEDTIME_LENGTH);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

int
shishi_encticketpart_authtime (Shishi * handle,
			       Shishi_asn1 encticketpart,
			       char *authtime, size_t * authtimelen)
{
  return shishi_asn1_read_inline (handle, encticketpart, "authtime",
				  authtime, authtimelen);
}

time_t
shishi_encticketpart_authctime (Shishi * handle, Shishi_asn1 encticketpart)
{
  char authtime[SHISHI_GENERALIZEDTIME_LENGTH + 1];
  size_t authtimelen;
  time_t t;
  int res;

  authtimelen = sizeof (authtime);
  res = shishi_encticketpart_authtime (handle, encticketpart,
				       authtime, &authtimelen);
  if (res != SHISHI_OK)
    return (time_t) - 1;

  authtime[SHISHI_GENERALIZEDTIME_LENGTH] = '\0';

  t = shishi_generalize_ctime (handle, authtime);

  return t;
}

/**
 * shishi_encticketpart_client:
 * @handle: Shishi library handle create by shishi_init().
 * @encticketpart: EncTicketPart variable to get client name from.
 * @client: pointer to newly allocated zero terminated string containing
 *   principal name.  May be %NULL (to only populate @clientlen).
 * @clientlen: pointer to length of @client on output, excluding terminating
 *   zero.  May be %NULL (to only populate @client).
 *
 * Represent client principal name in EncTicketPart as zero-terminated
 * string.  The string is allocate by this function, and it is the
 * responsibility of the caller to deallocate it.  Note that the
 * output length @clientlen does not include the terminating zero.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_encticketpart_client (Shishi * handle,
			     Shishi_asn1 encticketpart,
			     char **client, size_t * clientlen)
{
  return shishi_principal_name (handle, encticketpart, "cname",
				client, clientlen);
}

/**
 * shishi_encticketpart_clientrealm:
 * @handle: Shishi library handle create by shishi_init().
 * @encticketpart: EncTicketPart variable to get client name and realm from.
 * @client: pointer to newly allocated zero terminated string containing
 *   principal name and realm.  May be %NULL (to only populate @clientlen).
 * @clientlen: pointer to length of @client on output, excluding terminating
 *   zero.  May be %NULL (to only populate @client).
 *
 * Convert cname and realm fields from EncTicketPart to printable
 * principal name format.  The string is allocate by this function,
 * and it is the responsibility of the caller to deallocate it.  Note
 * that the output length @clientlen does not include the terminating
 * zero.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_encticketpart_clientrealm (Shishi * handle,
				  Shishi_asn1 encticketpart,
				  char **client, size_t * clientlen)
{
  return shishi_principal_name_realm (handle,
				      encticketpart, "cname",
				      encticketpart, "crealm",
				      client, clientlen);
}
