/* enckdcreppart.c --- Key distribution encrypted reply part functions
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


Shishi_asn1
shishi_enckdcreppart (Shishi * handle)
{
  int res;
  Shishi_asn1 node;

  node = shishi_asn1_enckdcreppart (handle);
  if (!node)
    return NULL;

  /* XXX remove these two: */
  res = shishi_asn1_write (handle, node, "key-expiration", NULL, 0);
  if (res != SHISHI_OK)
    return NULL;

  res = shishi_asn1_write (handle, node, "caddr", NULL, 0);
  if (res != SHISHI_OK)
    return NULL;

  res = shishi_enckdcreppart_flags_set (handle, node, 0);
  if (res != SHISHI_OK)
    return NULL;

  return node;
}

Shishi_asn1
shishi_encasreppart (Shishi * handle)
{
  int res;
  Shishi_asn1 node;

  node = shishi_asn1_encasreppart (handle);
  if (!node)
    return NULL;

  /* XXX remove these two: */
  res = shishi_asn1_write (handle, node, "key-expiration", NULL, 0);
  if (res != SHISHI_OK)
    puts ("urk");
  res = shishi_asn1_write (handle, node, "caddr", NULL, 0);
  if (res != SHISHI_OK)
    puts ("urk2");

  return node;
}

/**
 * shishi_enckdcreppart_get_key:
 * @handle: shishi handle as allocated by shishi_init().
 * @enckdcreppart: input EncKDCRepPart variable.
 * @key: newly allocated encryption key handle.
 *
 * Extract the key to use with the ticket sent in the KDC-REP
 * associated with the EncKDCRepPart input variable.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_enckdcreppart_get_key (Shishi * handle,
			      Shishi_asn1 enckdcreppart, Shishi_key ** key)
{
  int res;
  char *buf;
  size_t buflen;
  int32_t keytype;

  res = shishi_asn1_read_int32 (handle, enckdcreppart,
				"key.keytype", &keytype);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_read (handle, enckdcreppart, "key.keyvalue",
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
 * shishi_enckdcreppart_key_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @enckdcreppart: input EncKDCRepPart variable.
 * @key: key handle with information to store in enckdcreppart.
 *
 * Set the EncKDCRepPart.key field to key type and value of supplied
 * key.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_enckdcreppart_key_set (Shishi * handle,
			      Shishi_asn1 enckdcreppart, Shishi_key * key)
{
  int res;

  res = shishi_asn1_write_integer (handle, enckdcreppart, "key.keytype",
				   shishi_key_type (key));
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  res = shishi_asn1_write (handle, enckdcreppart, "key.keyvalue",
			   shishi_key_value (key), shishi_key_length (key));
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_enckdcreppart_nonce_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @enckdcreppart: input EncKDCRepPart variable.
 * @nonce: nonce to set in EncKDCRepPart.
 *
 * Set the EncKDCRepPart.nonce field.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_enckdcreppart_nonce_set (Shishi * handle,
				Shishi_asn1 enckdcreppart, uint32_t nonce)
{
  int res;

  res = shishi_asn1_write_uint32 (handle, enckdcreppart, "nonce", nonce);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_enckdcreppart_flags_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @enckdcreppart: input EncKDCRepPart variable.
 * @flags: flags to set in EncKDCRepPart.
 *
 * Set the EncKDCRepPart.flags field.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_enckdcreppart_flags_set (Shishi * handle,
				Shishi_asn1 enckdcreppart, int flags)
{
  int res;

  res = shishi_asn1_write_bitstring (handle, enckdcreppart, "flags", flags);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_enckdcreppart_authtime_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @enckdcreppart: input EncKDCRepPart variable.
 * @authtime: character buffer containing a generalized time string.
 *
 * Set the EncTicketPart.authtime to supplied value.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_enckdcreppart_authtime_set (Shishi * handle,
				   Shishi_asn1 enckdcreppart,
				   const char *authtime)
{
  int res;

  res = shishi_asn1_write (handle, enckdcreppart, "authtime",
			   authtime, SHISHI_GENERALIZEDTIME_LENGTH);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_enckdcreppart_starttime_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @enckdcreppart: input EncKDCRepPart variable.
 * @starttime: character buffer containing a generalized time string.
 *
 * Set the EncTicketPart.starttime to supplied value.  Use a NULL
 * value for @starttime to remove the field.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_enckdcreppart_starttime_set (Shishi * handle,
				    Shishi_asn1 enckdcreppart,
				    const char *starttime)
{
  int res;

  if (!starttime)
    res = shishi_asn1_write (handle, enckdcreppart, "starttime", NULL, 0);
  else
    res = shishi_asn1_write (handle, enckdcreppart, "starttime",
			     starttime, SHISHI_GENERALIZEDTIME_LENGTH);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_enckdcreppart_endtime_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @enckdcreppart: input EncKDCRepPart variable.
 * @endtime: character buffer containing a generalized time string.
 *
 * Set the EncTicketPart.endtime to supplied value.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_enckdcreppart_endtime_set (Shishi * handle,
				  Shishi_asn1 enckdcreppart,
				  const char *endtime)
{
  int res;

  res = shishi_asn1_write (handle, enckdcreppart, "endtime",
			   endtime, SHISHI_GENERALIZEDTIME_LENGTH);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_enckdcreppart_renew_till_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @enckdcreppart: input EncKDCRepPart variable.
 * @renew_till: character buffer containing a generalized time string.
 *
 * Set the EncTicketPart.renew-till to supplied value.  Use a NULL
 * value for @renew_till to remove the field.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_enckdcreppart_renew_till_set (Shishi * handle,
				     Shishi_asn1 enckdcreppart,
				     const char *renew_till)
{
  int res;

  if (!renew_till)
    res = shishi_asn1_write (handle, enckdcreppart, "renew-till", NULL, 0);
  else
    res = shishi_asn1_write (handle, enckdcreppart, "renew-till",
			     renew_till, SHISHI_GENERALIZEDTIME_LENGTH);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_enckdcreppart_srealm_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @enckdcreppart: EncKDCRepPart variable to set realm field in.
 * @srealm: input array with name of realm.
 *
 * Set the server realm field in the EncKDCRepPart.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_enckdcreppart_srealm_set (Shishi * handle,
				 Shishi_asn1 enckdcreppart,
				 const char *srealm)
{
  int res = SHISHI_OK;

  res = shishi_asn1_write (handle, enckdcreppart, "srealm", srealm, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}


/**
 * shishi_enckdcreppart_sname_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @enckdcreppart: EncKDCRepPart variable to set server name field in.
 * @name_type: type of principial, see Shishi_name_type, usually
 *             SHISHI_NT_UNKNOWN.
 * @sname: input array with principal name.
 *
 * Set the server name field in the EncKDCRepPart.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_enckdcreppart_sname_set (Shishi * handle,
				Shishi_asn1 enckdcreppart,
				Shishi_name_type name_type, char *sname[])
{
  int res = SHISHI_OK;
  int i;
  char *buf;

  res = shishi_asn1_write_integer (handle, enckdcreppart,
				   "sname.name-type", name_type);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, enckdcreppart,
			   "sname.name-string", NULL, 0);
  if (res != SHISHI_OK)
    return res;

  i = 1;
  while (sname[i - 1])
    {
      res = shishi_asn1_write (handle, enckdcreppart, "sname.name-string",
			       "NEW", 1);
      if (res != SHISHI_OK)
	return res;

      asprintf (&buf, "sname.name-string.?%d", i);
      res = shishi_asn1_write (handle, enckdcreppart, buf, sname[i - 1], 0);
      free (buf);
      if (res != SHISHI_OK)
	return res;

      i++;
    }

  return SHISHI_OK;
}

int
shishi_enckdcreppart_server_set (Shishi * handle,
				 Shishi_asn1 enckdcreppart,
				 const char *server)
{
  char *tmpserver;
  char **serverbuf;
  char *tokptr = NULL;
  int res;
  int i;

  tmpserver = xstrdup (server);

  serverbuf = xmalloc (sizeof (*serverbuf));
  for (i = 0;
       (serverbuf[i] = strtok_r (i == 0 ? tmpserver : NULL, "/", &tokptr));
       i++)
    {
      serverbuf = xrealloc (serverbuf, (i + 2) * sizeof (*serverbuf));
    }

  res = shishi_enckdcreppart_sname_set (handle, enckdcreppart,
					SHISHI_NT_PRINCIPAL, serverbuf);
  if (res != SHISHI_OK)
    return res;

  free (serverbuf);
  free (tmpserver);

  return SHISHI_OK;
}

int
shishi_enckdcreppart_srealmserver_set (Shishi * handle,
				       Shishi_asn1 enckdcreppart,
				       const char *srealm, const char *server)
{
  int res;

  res = shishi_enckdcreppart_srealm_set (handle, enckdcreppart, srealm);
  if (res != SHISHI_OK)
    return res;

  res = shishi_enckdcreppart_server_set (handle, enckdcreppart, server);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_enckdcreppart_populate_encticketpart:
 * @handle: shishi handle as allocated by shishi_init().
 * @enckdcreppart: input EncKDCRepPart variable.
 * @encticketpart: input EncTicketPart variable.
 *
 * Set the flags, authtime, starttime, endtime, renew-till and caddr
 * fields of the EncKDCRepPart to the corresponding values in the
 * EncTicketPart.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_enckdcreppart_populate_encticketpart (Shishi * handle,
					     Shishi_asn1 enckdcreppart,
					     Shishi_asn1 encticketpart)
{
  char *buf;
  size_t buflen;
  int res;

  res = shishi_asn1_read (handle, encticketpart, "flags", &buf, &buflen);
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  res = shishi_asn1_write (handle, enckdcreppart, "flags", buf, buflen);
  free (buf);
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  res = shishi_asn1_read (handle, encticketpart, "authtime", &buf, &buflen);
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  res = shishi_asn1_write (handle, enckdcreppart, "authtime", buf, buflen);
  free (buf);
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  res = shishi_asn1_read (handle, encticketpart, "starttime", &buf, &buflen);
  if (res != SHISHI_OK && res != SHISHI_ASN1_NO_ELEMENT)
    return SHISHI_ASN1_ERROR;

  if (res == SHISHI_ASN1_NO_ELEMENT)
    res = shishi_asn1_write (handle, enckdcreppart, "starttime", NULL, 0);
  else
    {
      res = shishi_asn1_write (handle, enckdcreppart, "starttime",
			       buf, buflen);
      free (buf);
    }
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  res = shishi_asn1_read (handle, encticketpart, "endtime", &buf, &buflen);
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  res = shishi_asn1_write (handle, enckdcreppart, "endtime", buf, buflen);
  free (buf);
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  res = shishi_asn1_read (handle, encticketpart, "renew-till", &buf, &buflen);
  if (res != SHISHI_OK && res != SHISHI_ASN1_NO_ELEMENT)
    return SHISHI_ASN1_ERROR;

  if (res == SHISHI_ASN1_NO_ELEMENT)
    res = shishi_asn1_write (handle, enckdcreppart, "renew-till", NULL, 0);
  else
    {
      res = shishi_asn1_write (handle, enckdcreppart,
			       "renew-till", buf, buflen);
      free (buf);
    }
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  /* XXX copy caddr too */

  return SHISHI_OK;
}
