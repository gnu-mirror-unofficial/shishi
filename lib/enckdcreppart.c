/* enckdcreppart.c	Key distribution encrypted reply part functions
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
			      ASN1_TYPE enckdcreppart, Shishi_key ** key)
{
  int res;
  char buf[BUFSIZ];
  int buflen;
  int keytype;

  res = shishi_asn1_integer_field (handle, enckdcreppart, &keytype,
				   "EncKDCRepPart.key.keytype");
  if (res != SHISHI_OK)
    return res;

  buflen = BUFSIZ;
  res = shishi_asn1_field (handle, enckdcreppart, buf, &buflen,
			   "EncKDCRepPart.key.keyvalue");
  if (res != ASN1_SUCCESS)
    return res;

  res = shishi_key_from_value (handle, keytype, buf, key);
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
			      ASN1_TYPE enckdcreppart, Shishi_key * key)
{
  int res;
  char buf[BUFSIZ];
  int keytype;

  keytype = shishi_key_type (key);
  sprintf (buf, "%d", keytype);
  res = asn1_write_value (enckdcreppart, "EncKDCRepPart.key.keytype", buf, 0);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  res = asn1_write_value (enckdcreppart, "EncKDCRepPart.key.keyvalue",
			  shishi_key_value (key), shishi_key_length (key));
  if (res != ASN1_SUCCESS)
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
				ASN1_TYPE enckdcreppart,
				unsigned long nonce)
{
  int res;
  char buf[BUFSIZ];

  sprintf (buf, "%d", nonce);
  res = asn1_write_value (enckdcreppart, "EncKDCRepPart.nonce", buf, 0);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

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
					     ASN1_TYPE enckdcreppart,
					     ASN1_TYPE encticketpart)
{
  unsigned char buf[BUFSIZ];
  int buflen;
  int res;

  buflen = BUFSIZ;
  res = asn1_read_value (encticketpart, "EncTicketPart.flags", buf, &buflen);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  res = asn1_write_value (enckdcreppart, "EncKDCRepPart.flags", buf, buflen);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  buflen = BUFSIZ;
  res = asn1_read_value (encticketpart, "EncTicketPart.authtime",
			 buf, &buflen);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  res = asn1_write_value (enckdcreppart, "EncKDCRepPart.authtime",
			  buf, buflen);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  buflen = BUFSIZ;
  res = asn1_read_value (encticketpart, "EncTicketPart.starttime",
			 buf, &buflen);
  if (res != ASN1_SUCCESS && res != ASN1_ELEMENT_NOT_FOUND)
    return SHISHI_ASN1_ERROR;

  if (res == ASN1_ELEMENT_NOT_FOUND)
    res = asn1_write_value (enckdcreppart, "EncKDCRepPart.starttime", NULL, 0);
  else
    res = asn1_write_value (enckdcreppart, "EncKDCRepPart.starttime",
			    buf, buflen);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  buflen = BUFSIZ;
  res = asn1_read_value (encticketpart, "EncTicketPart.endtime", buf, &buflen);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  res = asn1_write_value (enckdcreppart, "EncKDCRepPart.endtime", buf, buflen);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  buflen = BUFSIZ;
  res = asn1_read_value (encticketpart, "EncTicketPart.renew-till",
			 buf, &buflen);
  if (res != ASN1_SUCCESS && res != ASN1_ELEMENT_NOT_FOUND)
    return SHISHI_ASN1_ERROR;

  if (res == ASN1_ELEMENT_NOT_FOUND)
    res = asn1_write_value (enckdcreppart, "EncKDCRepPart.renew-till",
			    NULL, 0);
  else
    res = asn1_write_value (enckdcreppart, "EncKDCRepPart.renew-till",
			    buf, buflen);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  /* XXX copy caddr too */

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
				 ASN1_TYPE enckdcreppart,
				 const char *srealm)
{
  int res = ASN1_SUCCESS;

  res = asn1_write_value (enckdcreppart, "EncKDCRepPart.srealm", srealm, 0);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return !SHISHI_OK;
    }

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
				ASN1_TYPE enckdcreppart,
				Shishi_name_type name_type, char *sname[])
{
  int res = ASN1_SUCCESS;
  char buf[BUFSIZ];
  int i;

  sprintf (buf, "%d", name_type);

  res = asn1_write_value (enckdcreppart,
			  "EncKDCRepPart.sname.name-type", buf, 0);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return !SHISHI_OK;
    }

  res =
    asn1_write_value (enckdcreppart,
		      "EncKDCRepPart.sname.name-string", NULL, 0);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return !SHISHI_OK;
    }

  i = 1;
  while (sname[i - 1])
    {
      res = asn1_write_value (enckdcreppart, "EncKDCRepPart.sname.name-string",
			      "NEW", 1);
      if (res != ASN1_SUCCESS)
	{
	  shishi_error_set (handle, libtasn1_strerror (res));
	  return !SHISHI_OK;
	}

      sprintf (buf, "EncKDCRepPart.sname.name-string.?%d", i);
      res = asn1_write_value (enckdcreppart, buf, sname[i - 1], 0);
      if (res != ASN1_SUCCESS)
	{
	  shishi_error_set (handle, libtasn1_strerror (res));
	  return !SHISHI_OK;
	}

      i++;
    }

  return SHISHI_OK;
}

int
shishi_enckdcreppart_server_set (Shishi * handle,
				 ASN1_TYPE enckdcreppart,
				 const char *server)
{
  char *tmpserver;
  char **serverbuf;
  char *tokptr;
  int res;
  int i;

  tmpserver = strdup (server);
  if (tmpserver == NULL)
    return SHISHI_MALLOC_ERROR;

  serverbuf = malloc (sizeof (*serverbuf));
  for (i = 0;
       (serverbuf[i] = strtok_r (i == 0 ? tmpserver : NULL, "/", &tokptr));
       i++)
    {
      serverbuf = realloc (serverbuf, (i + 2) * sizeof (*serverbuf));
      if (serverbuf == NULL)
	return SHISHI_MALLOC_ERROR;
    }
  res = shishi_enckdcreppart_sname_set (handle, enckdcreppart,
					SHISHI_NT_PRINCIPAL, serverbuf);
  if (res != SHISHI_OK)
    {
      fprintf (stderr, _("Could not set sname: %s\n"),
	       shishi_strerror_details (handle));
      return res;
    }
  free (serverbuf);
  free (tmpserver);

  return SHISHI_OK;
}

int
shishi_enckdcreppart_srealmserver_set (Shishi * handle,
				       ASN1_TYPE enckdcreppart,
				       const char *srealm,
				       const char *server)
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

ASN1_TYPE
shishi_enckdcreppart (Shishi * handle)
{
  int res = ASN1_SUCCESS;
  ASN1_TYPE node = ASN1_TYPE_EMPTY;

  res = asn1_create_element (handle->asn1, "Kerberos5.EncKDCRepPart",
			     &node, "EncKDCRepPart");
  if (res != ASN1_SUCCESS)
    goto error;

  /* XXX remove these two: */
  res = asn1_write_value (node, "EncKDCRepPart.key-expiration", NULL, 0);
  if (res != ASN1_SUCCESS)
    goto error;
  res = asn1_write_value (node, "EncKDCRepPart.caddr", NULL, 0);
  if (res != ASN1_SUCCESS)
    goto error;

  return node;

error:
  shishi_error_set (handle, libtasn1_strerror (res));
  if (node != ASN1_TYPE_EMPTY)
    asn1_delete_structure (&node);
  return NULL;
}

ASN1_TYPE
shishi_encasreppart (Shishi * handle)
{
  int res = ASN1_SUCCESS;
  ASN1_TYPE node = ASN1_TYPE_EMPTY;

  res = asn1_create_element (handle->asn1, "Kerberos5.EncASRepPart",
			     &node, "EncKDCRepPart");
  if (res != ASN1_SUCCESS)
    goto error;

  /* XXX remove these two: */
  res = asn1_write_value (node, "EncKDCRepPart.key-expiration", NULL, 0);
  if (res != ASN1_SUCCESS)
    goto error;
  res = asn1_write_value (node, "EncKDCRepPart.caddr", NULL, 0);
  if (res != ASN1_SUCCESS)
    goto error;

  return node;

 error:
  shishi_error_set (handle, libtasn1_strerror (res));
  if (node != ASN1_TYPE_EMPTY)
    asn1_delete_structure (&node);
  return NULL;
}
