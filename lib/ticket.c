/* ticket.c	low-level ASN.1 Ticket handling
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

int
shishi_ticket_realm_get (Shishi * handle,
			 ASN1_TYPE ticket, char *realm, int *realmlen)
{
  return shishi_asn1_field (handle, ticket, realm, realmlen, "Ticket.realm");
}

/**
 * shishi_ticket_realm_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @ticket: input variable with ticket info.
 * @realm: input array with name of realm.
 *
 * Set the realm field in the Ticket.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ticket_realm_set (Shishi * handle, ASN1_TYPE ticket, const char *realm)
{
  int res = ASN1_SUCCESS;

  res = asn1_write_value (ticket, "Ticket.realm", realm, 0);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  return SHISHI_OK;
}

int
shishi_ticket_sname_get (Shishi * handle,
			 ASN1_TYPE ticket, char *server, int *serverlen)
{
  return shishi_principal_name_get (handle, ticket, "Ticket.sname",
				    server, serverlen);
}

/**
 * shishi_ticket_sname_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @ticket: Ticket variable to set server name field in.
 * @name_type: type of principial, see Shishi_name_type, usually
 *             SHISHI_NT_UNKNOWN.
 * @sname: input array with principal name.
 *
 * Set the server name field in the Ticket.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ticket_sname_set (Shishi * handle,
			 ASN1_TYPE ticket,
			 Shishi_name_type name_type, char *sname[])
{
  int res = ASN1_SUCCESS;
  char buf[BUFSIZ];
  int i;

  sprintf (buf, "%d", name_type);

  res = asn1_write_value (ticket, "Ticket.sname.name-type", buf, 0);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return !SHISHI_OK;
    }

  res = asn1_write_value (ticket, "Ticket.sname.name-string", NULL, 0);
  if (res != ASN1_SUCCESS)
    {
      shishi_error_set (handle, libtasn1_strerror (res));
      return !SHISHI_OK;
    }

  i = 1;
  while (sname[i - 1])
    {
      res = asn1_write_value (ticket, "Ticket.sname.name-string", "NEW", 1);
      if (res != ASN1_SUCCESS)
	{
	  shishi_error_set (handle, libtasn1_strerror (res));
	  return !SHISHI_OK;
	}

      sprintf (buf, "Ticket.sname.name-string.?%d", i);
      res = asn1_write_value (ticket, buf, sname[i - 1], 0);
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
shishi_ticket_set_server (Shishi * handle,
			  ASN1_TYPE ticket, const char *server)
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
  res = shishi_ticket_sname_set (handle, ticket,
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
shishi_ticket_snamerealm_get (Shishi * handle,
			      ASN1_TYPE ticket,
			      char *serverrealm, int *serverrealmlen)
{
  return shishi_principal_name_realm_get (handle, ticket, "Ticket.sname",
					  ticket, "Ticket.realm",
					  serverrealm, serverrealmlen);
}

int
shishi_ticket_srealmserver_set (Shishi * handle,
				ASN1_TYPE ticket, char *realm, char *server)
{
  int res;

  res = shishi_ticket_realm_set (handle, ticket, realm);
  if (res != SHISHI_OK)
    return res;

  res = shishi_ticket_set_server (handle, ticket, server);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_ticket_get_enc_part_etype:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcrep: Ticket variable to get value from.
 * @etype: output variable that holds the value.
 *
 * Extract Ticket.enc-part.etype.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ticket_get_enc_part_etype (Shishi * handle,
				  ASN1_TYPE ticket, int *etype)
{
  int buflen;
  int res;

  *etype = 0;
  buflen = sizeof (*etype);
  res = shishi_asn1_field (handle, ticket,
			   (char *) etype, &buflen, "Ticket.enc-part.etype");

  return res;
}

int
shishi_ticket_decrypt (Shishi * handle,
		       ASN1_TYPE ticket,
		       Shishi_key * key, ASN1_TYPE * encticketpart)
{
  int res;
  int i;
  int buflen = BUFSIZ;
  unsigned char buf[BUFSIZ];
  unsigned char cipher[BUFSIZ];
  int cipherlen;
  int etype;

  res = shishi_ticket_get_enc_part_etype (handle, ticket, &etype);
  if (res != SHISHI_OK)
    return res;

  if (etype != shishi_key_type (key))
    return SHISHI_TICKET_BAD_KEYTYPE;

  cipherlen = BUFSIZ;
  res = shishi_asn1_field (handle, ticket, cipher, &cipherlen,
			   "Ticket.enc-part.cipher");
  if (res != SHISHI_OK)
    return res;

  res = shishi_decrypt (handle, key, SHISHI_KEYUSAGE_ENCTICKETPART,
			cipher, cipherlen, buf, &buflen);

  if (res != SHISHI_OK)
    {
      if (VERBOSE (handle))
	printf ("des_decrypt failed: %s\n", shishi_strerror_details (handle));
      shishi_error_printf (handle,
			   "des_decrypt fail, most likely wrong password\n");
      return SHISHI_TICKET_DECRYPT_FAILED;
    }

  /* The crypto is so 1980; no length indicator. Trim off pad bytes
     until we can parse it. */
  for (i = 0; i < 8; i++)
    {
      if (VERBOSEASN1 (handle))
	printf ("Trying with %d pad in enckdcrep...\n", i);

      *encticketpart = shishi_d2a_encticketpart (handle, &buf[0], buflen - i);
      if (*encticketpart != ASN1_TYPE_EMPTY)
	break;
    }

  if (*encticketpart == ASN1_TYPE_EMPTY)
    {
      shishi_error_printf (handle, "Could not DER decode EncTicketPart. "
			   "Password probably correct (decrypt ok) though\n");
      return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}

/**
 * shishi_ticket_set_enc_part:
 * @handle: shishi handle as allocated by shishi_init().
 * @ticket: Ticket to add enc-part field to.
 * @etype: encryption type used to encrypt enc-part.
 * @kvno: key version number.
 * @buf: input array with encrypted enc-part.
 * @buflen: size of input array with encrypted enc-part.
 *
 * Set the encrypted enc-part field in the Ticket.  The encrypted data
 * is usually created by calling shishi_encrypt() on the DER encoded
 * enc-part.  To save time, you may want to use
 * shishi_ticket_add_enc_part() instead, which calculates the
 * encrypted data and calls this function in one step.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ticket_set_enc_part (Shishi * handle,
			    ASN1_TYPE ticket,
			    int etype, int kvno, char *buf, int buflen)
{
  char format[BUFSIZ];
  int res = ASN1_SUCCESS;

  res = asn1_write_value (ticket, "Ticket.enc-part.cipher", buf, buflen);
  if (res != ASN1_SUCCESS)
    goto error;

  sprintf (format, "%d", etype);
  res = asn1_write_value (ticket, "Ticket.enc-part.etype", format, 0);
  if (res != ASN1_SUCCESS)
    goto error;

  if (kvno == 0)
    {
      res = asn1_write_value (ticket, "Ticket.enc-part.kvno", NULL, 0);
      if (res != ASN1_SUCCESS)
	goto error;
    }
  else
    {
      shishi_asprintf (&format, "%d", etype);
      res = asn1_write_value (ticket, "Ticket.enc-part.kvno", format, 0);
      if (res != ASN1_SUCCESS)
	goto error;
    }

  return SHISHI_OK;

error:
  shishi_error_set (handle, libtasn1_strerror (res));
  return SHISHI_ASN1_ERROR;
}

/**
 * shishi_ticket_add_enc_part:
 * @handle: shishi handle as allocated by shishi_init().
 * @ticket: Ticket to add enc-part field to.
 * @key: key used to encrypt enc-part.
 * @encticketpart: EncTicketPart to add.
 *
 * Encrypts DER encoded EncTicketPart using key and stores it in the
 * Ticket.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ticket_add_enc_part (Shishi * handle,
			    ASN1_TYPE ticket,
			    Shishi_key * key, ASN1_TYPE encticketpart)
{
  int res = ASN1_SUCCESS;
  char buf[BUFSIZ];
  int buflen;
  char der[BUFSIZ];
  size_t derlen;

  res = shishi_a2d (handle, encticketpart, der, &derlen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not DER encode encticketpart: %s\n",
			   shishi_strerror (res));
      return !SHISHI_OK;
    }

  buflen = BUFSIZ;
  res = shishi_encrypt (handle, key, SHISHI_KEYUSAGE_ENCTICKETPART,
			der, derlen, buf, &buflen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "des_encrypt fail\n");
      return res;
    }

  res = shishi_ticket_set_enc_part (handle, ticket, shishi_key_type (key),
				    shishi_key_version (key), buf, buflen);

  return res;
}
