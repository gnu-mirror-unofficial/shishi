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


Shishi_asn1
shishi_enckdcreppart (Shishi * handle)
{
  int res;
  Shishi_asn1 node;

  node = shishi_asn1_enckdcreppart (handle);
  if (!node)
    return NULL;

  /* XXX remove these two: */
  res = shishi_asn1_write (handle, node, "EncKDCRepPart.key-expiration",
			   NULL, 0);
  if (res != SHISHI_OK)
    puts ("urk");
  res = shishi_asn1_write (handle, node, "EncKDCRepPart.caddr", NULL, 0);
  if (res != SHISHI_OK)
    puts ("urk2");

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
  res = shishi_asn1_write (handle, node, "EncKDCRepPart.key-expiration",
			   NULL, 0);
  if (res != SHISHI_OK)
    puts ("urk");
  res = shishi_asn1_write (handle, node, "EncKDCRepPart.caddr", NULL, 0);
  if (res != SHISHI_OK)
    puts ("urk2");

  return node;
}

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
			      Shishi_asn1 enckdcreppart, Shishi_key ** key)
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
  if (res != SHISHI_OK)
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
			      Shishi_asn1 enckdcreppart, Shishi_key * key)
{
  int res;
  char buf[BUFSIZ];
  int keytype;

  keytype = shishi_key_type (key);
  sprintf (buf, "%d", keytype);
  res = shishi_asn1_write (handle, enckdcreppart, "EncKDCRepPart.key.keytype",
			   buf, 0);
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  res = shishi_asn1_write (handle, enckdcreppart,
			   "EncKDCRepPart.key.keyvalue",
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
				Shishi_asn1 enckdcreppart,
				unsigned long nonce)
{
  int res;
  char *format;

  shishi_asprintf (&format, "%ld", nonce);
  res = shishi_asn1_write (handle, enckdcreppart, "EncKDCRepPart.nonce",
			   format, 0);
  free (format);
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
  char buf[BUFSIZ];

  sprintf (buf, "%d", flags);
  res = shishi_asn1_write (handle, enckdcreppart, "EncKDCRepPart.flags",
			   buf, 0);
  if (res != SHISHI_OK)
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
					     Shishi_asn1 enckdcreppart,
					     Shishi_asn1 encticketpart)
{
  unsigned char buf[BUFSIZ];
  int buflen;
  int res;

  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, encticketpart, "EncTicketPart.flags",
			  buf, &buflen);
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  res = shishi_asn1_write (handle, enckdcreppart, "EncKDCRepPart.flags",
			   buf, buflen);
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, encticketpart, "EncTicketPart.authtime",
			  buf, &buflen);
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  res = shishi_asn1_write (handle, enckdcreppart, "EncKDCRepPart.authtime",
			   buf, buflen);
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, encticketpart, "EncTicketPart.starttime",
			  buf, &buflen);
  if (res != SHISHI_OK && res != SHISHI_ASN1_NO_ELEMENT)
    return SHISHI_ASN1_ERROR;

  if (res == SHISHI_ASN1_NO_ELEMENT)
    res = shishi_asn1_write (handle, enckdcreppart, "EncKDCRepPart.starttime",
			     NULL, 0);
  else
    res = shishi_asn1_write (handle, enckdcreppart, "EncKDCRepPart.starttime",
			     buf, buflen);
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, encticketpart, "EncTicketPart.endtime",
			  buf, &buflen);
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  res = shishi_asn1_write (handle, enckdcreppart, "EncKDCRepPart.endtime",
			   buf, buflen);
  if (res != SHISHI_OK)
    return SHISHI_ASN1_ERROR;

  buflen = BUFSIZ;
  res = shishi_asn1_read (handle, encticketpart, "EncTicketPart.renew-till",
			  buf, &buflen);
  if (res != SHISHI_OK && res != SHISHI_ASN1_NO_ELEMENT)
    return SHISHI_ASN1_ERROR;

  if (res == SHISHI_ASN1_NO_ELEMENT)
    res = shishi_asn1_write (handle, enckdcreppart,
			     "EncKDCRepPart.renew-till", NULL, 0);
  else
    res = shishi_asn1_write (handle, enckdcreppart,
			     "EncKDCRepPart.renew-till", buf, buflen);
  if (res != SHISHI_OK)
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
				 Shishi_asn1 enckdcreppart,
				 const char *srealm)
{
  int res = SHISHI_OK;

  res = shishi_asn1_write (handle, enckdcreppart,
			   "EncKDCRepPart.srealm", srealm, 0);
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
  char buf[BUFSIZ];
  int i;

  sprintf (buf, "%d", name_type);

  res = shishi_asn1_write (handle, enckdcreppart,
			   "EncKDCRepPart.sname.name-type", buf, 0);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, enckdcreppart,
			   "EncKDCRepPart.sname.name-string", NULL, 0);
  if (res != SHISHI_OK)
    return res;

  i = 1;
  while (sname[i - 1])
    {
      res = shishi_asn1_write (handle, enckdcreppart,
			       "EncKDCRepPart.sname.name-string", "NEW", 1);
      if (res != SHISHI_OK)
	return res;

      sprintf (buf, "EncKDCRepPart.sname.name-string.?%d", i);
      res = shishi_asn1_write (handle, enckdcreppart, buf, sname[i - 1], 0);
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
