/* as.c		High level client AS functions
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

/* TODO: add shishi_as_clientserver(h,p,a,client,server) and make the
   shishi_as_cnamerealmsname function take real cname/sname pointer
   arrays. */

/**
 * shishi_as_get_asreq:
 * @as: structure that holds information about AS exchange
 * 
 * Return value: Returns the generated AS-REQ packet from the AS
 *               exchange, or NULL if not yet set or an error occured.
 **/
ASN1_TYPE
shishi_as_get_asreq (Shishi_as * as)
{
  return as->asreq;
}

/**
 * shishi_as_get_asrep:
 * @as: structure that holds information about AS exchange
 * 
 * Return value: Returns the received AS-REP packet from the AS
 *               exchange, or NULL if not yet set or an error occured.
 **/
ASN1_TYPE
shishi_as_get_asrep (Shishi_as * as)
{
  return as->asrep;
}

/**
 * shishi_as_get_krberror:
 * @as: structure that holds information about AS exchange
 * 
 * Return value: Returns the received KRB-ERROR packet from the AS
 *               exchange, or NULL if not yet set or an error occured.
 **/
ASN1_TYPE
shishi_as_get_krberror (Shishi_as * as)
{
  return as->krberror;
}

/**
 * shishi_as_get_ticket:
 * @as: structure that holds information about AS exchange
 * 
 * Return value: Returns the newly aquired ticket from the AS
 *               exchange, or NULL if not yet set or an error occured.
 **/
Shishi_ticket *
shishi_as_get_ticket (Shishi_as * as)
{
  return as->ticket;
}

/**
 * shishi_as:
 * @handle: shishi handle as allocated by shishi_init().
 * @password: password of client, or NULL to query user.
 * @as: holds pointer to newly allocate Shishi_as structure.
 * 
 * Perform initial Kerberos 5 authentication, in order to acquire a
 * Ticket Granting Ticket.  It uses defaults from the handle for the
 * client principal name, server realm and server name.  The server name
 * is by default the ticket-granting server name of the realm.  The
 * password field holds a user supplied password, or NULL to make this
 * function query for one.
 * 
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_as (Shishi * handle, char *password, Shishi_as ** as)
{
  char *realm;
  char *server;
  char *client;
  int res;

  realm = shishi_realm_default_get (handle);

  server = malloc (strlen (KRBTGT PRINCIPAL_DELIMITER) + strlen (realm) + 1);
  if (server == NULL)
    return SHISHI_MALLOC_ERROR;

  sprintf (server, KRBTGT PRINCIPAL_DELIMITER "%s", realm);

  res = shishi_as_password_cnamerealmsname
    (handle, password, as,
     shishi_principal_default_get (handle), realm, server);

  free (server);

  return res;
}

/**
 * shishi_as_password_cnamerealmsname:
 * @handle: shishi handle as allocated by shishi_init().
 * @password: password of client, or NULL to query user.
 * @as: holds pointer to newly allocate Shishi_as structure.
 * @cname: client principal name
 * @realm: server realm (also indicates client realm)
 * @sname: server principal name
 * 
 * Perform initial Kerberos 5 authentication, in order to acquire a
 * Ticket Granting Ticket.  It uses the supplied values for the client
 * principal name, server realm and server name.  The server name
 * should normally be the ticket-granting server name of the realm.
 * The password field holds a user supplied password, or NULL to make
 * this function query for one.
 * 
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_as_password_cnamerealmsname (Shishi * handle,
				    char *password,
				    Shishi_as ** as,
				    char *cname, char *realm, char *sname)
{
  return shishi_as_cnamerealmsname (handle, -1, password, 0, as,
				    cname, realm, sname);

}


/**
 * shishi_as_rawkey_cnamerealmsname:
 * @handle: shishi handle as allocated by shishi_init().
 * @keytype: cryptographic encryption type, see Shishi_etype.
 * @key: input array with cryptographic key to use.
 * @keylen: size of input array with cryptographic key.
 * @as: holds pointer to newly allocate Shishi_as structure.
 * @cname: client principal name
 * @realm: server realm (also indicates client realm)
 * @sname: server principal name
 * 
 * Perform initial Kerberos 5 authentication, in order to acquire a
 * Ticket Granting Ticket.  It uses the supplied values for the client
 * principal name, server realm and server name.  The server name
 * should normally be the ticket-granting server name of the realm.
 * The key is used to decrypt the AP-REP, but also used when creating
 * the AP-REQ to indicate that the only supported encryption type is
 * the supplied keytype.
 * 
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_as_rawkey_cnamerealmsname (Shishi * handle,
				  int keytype,
				  char *key,
				  int keylen,
				  Shishi_as ** as,
				  char *cname, char *realm, char *sname)
{
  return shishi_as_cnamerealmsname (handle, keytype, key, keylen, as,
				    cname, realm, sname);
}

/**
 * shishi_as_cnamerealmsname:
 * @handle: shishi handle as allocated by shishi_init().
 * @keytype: cryptographic encryption type (see Shishi_etype), or -1.
 * @password: input array with cryptographic key or password string to use.
 * @keylen: size of input array with cryptographic key, or 0 if password.
 * @as: holds pointer to newly allocate Shishi_as structure.
 * @cname: client principal name
 * @realm: server realm (also indicates client realm)
 * @sname: server principal name
 * 
 * Perform initial Kerberos 5 authentication, in order to acquire a
 * Ticket Granting Ticket.  It uses the supplied values for the client
 * principal name, server realm and server name.  The server name
 * should normally be the ticket-granting server name of the realm.
 * If the keytype is -1, the password field holds a user supplied
 * password, or NULL to make this function query for one.  If the
 * keytype is not -1, the password is used as the raw encryption key
 * (of length specified by keylen), and it is used to decrypt the
 * AP-REP, but also used when creating the AP-REQ to indicate that the
 * only supported encryption type is the supplied keytype.
 * 
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_as_cnamerealmsname (Shishi * handle,
			   int keytype,
			   char *password,
			   int keylen,
			   Shishi_as ** as,
			   char *cname, char *realm, char *sname)
{
  const char *const key = password;
  char user[BUFSIZ];
  int userlen;
  int res;
  ASN1_TYPE ticket, kdcreppart;

  *as = malloc (sizeof (**as));
  if (*as == NULL)
    return SHISHI_MALLOC_ERROR;

  /* XXX use keytype to set etype in request */

  (*as)->asreq = shishi_asreq (handle, realm, sname, cname);
  if ((*as)->asreq == ASN1_TYPE_EMPTY)
    goto done;

  res = shishi_kdcreq_sendrecv (handle, (*as)->asreq, &(*as)->asrep);
  if (res == SHISHI_GOT_KRBERROR)
    {
      (*as)->krberror = (*as)->asrep;
      (*as)->asrep = NULL;
    }
  if (res != SHISHI_OK)
    goto done;

  if (keytype == -1 && password == NULL)
    {
      char password[BUFSIZ];

      res = shishi_prompt_password (handle,
				    stdin, password, BUFSIZ,
				    stdout, "Enter password for `%s@%s': ",
				    shishi_principal_default_get (handle),
				    shishi_realm_default_get (handle));
      if (res != SHISHI_OK)
	{
	  printf ("Reading password failed: %s\n%s", shishi_strerror (res));
	  return res;
	}
      res = shishi_as_process (handle, (*as)->asreq, (*as)->asrep,
			       password, &kdcreppart);
    }
  else if (keytype == -1)
    res = shishi_as_process (handle, (*as)->asreq, (*as)->asrep,
			     password, &kdcreppart);
  else
    res = shishi_kdc_process (handle, (*as)->asreq, (*as)->asrep,
			      SHISHI_KEYUSAGE_ENCASREPPART,
			      keytype, key, keylen, &kdcreppart);
  if (res != SHISHI_OK)
    goto done;

  res = shishi_kdcrep_get_ticket (handle, (*as)->asrep, &ticket);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not extract ticket from AS-REP: %s",
			   shishi_strerror_details (handle));
      return res;
    }

  userlen = sizeof (user);
  res = shishi_kdcreq_cnamerealm_get (handle, (*as)->asreq, user, &userlen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not extract cname AS-REP: %s\n",
			   shishi_strerror (res),
			   shishi_strerror_details (handle));
      return res;
    }
  user[userlen] = '\0';
  (*as)->ticket = shishi_ticket (handle, strdup (user), ticket, kdcreppart);
  if ((*as)->ticket == NULL)
    {
      shishi_error_printf (handle, "Could not create ticket");
      return SHISHI_MALLOC_ERROR;
    }

  return SHISHI_OK;

done:
  free (*as);
  return res;
}
