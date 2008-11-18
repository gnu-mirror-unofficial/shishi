/* ticket.c --- Low-level ASN.1 Ticket handling.
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

#define SHISHI_TICKET_DEFAULT_TKTVNO "5"
#define SHISHI_TICKET_DEFAULT_TKTVNO_LEN 0

/**
 * shishi_ticket:
 * @handle: shishi handle as allocated by shishi_init().
 *
 * This function creates a new ASN.1 Ticket, populated with some
 * default values.
 *
 * Return value: Returns the ticket or NULL on failure.
 **/
Shishi_asn1
shishi_ticket (Shishi * handle)
{
  Shishi_asn1 node = NULL;
  int rc;

  node = shishi_asn1_ticket (handle);
  if (!node)
    return NULL;

  rc = shishi_asn1_write (handle, node, "tkt-vno",
			  SHISHI_TICKET_DEFAULT_TKTVNO,
			  SHISHI_TICKET_DEFAULT_TKTVNO_LEN);
  if (rc != SHISHI_OK)
    goto error;

  return node;

error:
  shishi_asn1_done (handle, node);
  return NULL;
}

/**
 * shishi_ticket_realm_get:
 * @handle: shishi handle as allocated by shishi_init().
 * @ticket: input variable with ticket info.
 * @realm: output array with newly allocated name of realm in ticket.
 * @realmlen: size of output array.
 *
 * Extract realm from ticket.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ticket_realm_get (Shishi * handle,
			 Shishi_asn1 ticket, char **realm, size_t * realmlen)
{
  return shishi_asn1_read (handle, ticket, "realm", realm, realmlen);
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
shishi_ticket_realm_set (Shishi * handle, Shishi_asn1 ticket,
			 const char *realm)
{
  int res;

  res = shishi_asn1_write (handle, ticket, "realm", realm, 0);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_ticket_server:
 * @handle: Shishi library handle create by shishi_init().
 * @ticket: ASN.1 Ticket variable to get server name from.
 * @server: pointer to newly allocated zero terminated string containing
 *   principal name.  May be %NULL (to only populate @serverlen).
 * @serverlen: pointer to length of @server on output, excluding terminating
 *   zero.  May be %NULL (to only populate @server).
 *
 * Represent server principal name in Ticket as zero-terminated
 * string.  The string is allocate by this function, and it is the
 * responsibility of the caller to deallocate it.  Note that the
 * output length @serverlen does not include the terminating zero.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ticket_server (Shishi * handle, Shishi_asn1 ticket,
		      char **server, size_t * serverlen)
{
  return shishi_principal_name (handle, ticket, "sname", server, serverlen);
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
			 Shishi_asn1 ticket,
			 Shishi_name_type name_type, char *sname[])
{
  int res = SHISHI_OK;
  char *buf;
  int i;

  asprintf (&buf, "%d", name_type);
  res = shishi_asn1_write (handle, ticket, "sname.name-type", buf, 0);
  free (buf);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write (handle, ticket, "sname.name-string", NULL, 0);
  if (res != SHISHI_OK)
    return res;

  i = 1;
  while (sname[i - 1])
    {
      res = shishi_asn1_write (handle, ticket, "sname.name-string", "NEW", 1);
      if (res != SHISHI_OK)
	return res;

      asprintf (&buf, "sname.name-string.?%d", i);
      res = shishi_asn1_write (handle, ticket, buf, sname[i - 1], 0);
      free (buf);
      if (res != SHISHI_OK)
	return res;

      i++;
    }

  return SHISHI_OK;
}

int
shishi_ticket_set_server (Shishi * handle,
			  Shishi_asn1 ticket, const char *server)
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
  res = shishi_ticket_sname_set (handle, ticket,
				 SHISHI_NT_PRINCIPAL, serverbuf);
  if (res != SHISHI_OK)
    {
      fprintf (stderr, _("Could not set sname: %s\n"), shishi_error (handle));
      return res;
    }
  free (serverbuf);
  free (tmpserver);

  return SHISHI_OK;
}

int
shishi_ticket_srealmserver_set (Shishi * handle,
				Shishi_asn1 ticket,
				const char *realm, const char *server)
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
 * @ticket: Ticket variable to get value from.
 * @etype: output variable that holds the value.
 *
 * Extract Ticket.enc-part.etype.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ticket_get_enc_part_etype (Shishi * handle,
				  Shishi_asn1 ticket, int32_t * etype)
{
  int res;

  res = shishi_asn1_read_int32 (handle, ticket, "enc-part.etype", etype);

  return res;
}

int
shishi_ticket_decrypt (Shishi * handle,
		       Shishi_asn1 ticket,
		       Shishi_key * key, Shishi_asn1 * encticketpart)
{
  int res;
  int i;
  char *buf;
  size_t buflen;
  char *cipher;
  size_t cipherlen;
  int etype;

  res = shishi_ticket_get_enc_part_etype (handle, ticket, &etype);
  if (res != SHISHI_OK)
    return res;

  if (etype != shishi_key_type (key))
    return SHISHI_TICKET_BAD_KEYTYPE;

  res = shishi_asn1_read (handle, ticket, "enc-part.cipher",
			  &cipher, &cipherlen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_decrypt (handle, key, SHISHI_KEYUSAGE_ENCTICKETPART,
			cipher, cipherlen, &buf, &buflen);
  free (cipher);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle,
			   "Ticket decrypt failed, wrong password?\n");
      return SHISHI_TICKET_DECRYPT_FAILED;
    }

  /* The crypto is so 1980; no length indicator. Trim off pad bytes
     until we can parse it. */
  for (i = 0; i < 8; i++)
    {
      if (VERBOSEASN1 (handle))
	printf ("Trying with %d pad in enckdcrep...\n", i);

      *encticketpart = shishi_der2asn1_encticketpart (handle, &buf[0],
						      buflen - i);
      if (*encticketpart != NULL)
	break;
    }

  if (*encticketpart == NULL)
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
			    Shishi_asn1 ticket,
			    int32_t etype, uint32_t kvno,
			    const char *buf, size_t buflen)
{
  int res = SHISHI_OK;

  res = shishi_asn1_write (handle, ticket, "enc-part.cipher", buf, buflen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_asn1_write_int32 (handle, ticket, "enc-part.etype", etype);
  if (res != SHISHI_OK)
    return res;

  if (kvno == UINT32_MAX)
    res = shishi_asn1_write (handle, ticket, "enc-part.kvno", NULL, 0);
  else
    res = shishi_asn1_write_uint32 (handle, ticket, "enc-part.kvno", kvno);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
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
			    Shishi_asn1 ticket,
			    Shishi_key * key, Shishi_asn1 encticketpart)
{
  int res = SHISHI_OK;
  char *buf;
  size_t buflen;
  char *der;
  size_t derlen;

  res = shishi_asn1_to_der (handle, encticketpart, &der, &derlen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not DER encode encticketpart: %s\n",
			   shishi_strerror (res));
      return res;
    }

  res = shishi_encrypt (handle, key, SHISHI_KEYUSAGE_ENCTICKETPART,
			der, derlen, &buf, &buflen);

  free (der);

  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle,
			   "Cannot encrypt encrypted part of ticket\n");
      return res;
    }

  res = shishi_ticket_set_enc_part (handle, ticket, shishi_key_type (key),
				    shishi_key_version (key), buf, buflen);

  free (buf);

  return res;
}
