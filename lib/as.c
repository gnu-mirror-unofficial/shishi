/* as.c		High level client AS functions
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

struct Shishi_as
{
  Shishi *handle;
  ASN1_TYPE asreq;
  ASN1_TYPE asrep;
  ASN1_TYPE krberror;
  Shishi_ticket *ticket;
};

/**
 * shishi_as:
 * @handle: shishi handle as allocated by shishi_init().
 * @as: holds pointer to newly allocate Shishi_as structure.
 *
 * Allocate a new AS exchange variable.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_as (Shishi * handle, Shishi_as ** as)
{
  Shishi_as *las;

  *as = malloc (sizeof (**as));
  if (*as == NULL)
    return SHISHI_MALLOC_ERROR;
  las = *as;
  memset (las, 0, sizeof (*las));

  las->handle = handle;

  las->asreq = shishi_asreq (handle);
  if (las->asreq == NULL)
    {
      shishi_error_printf (handle, "Could not create AS-REQ: %s\n",
			   shishi_strerror_details (handle));
      return SHISHI_ASN1_ERROR;
    }

  las->asrep = shishi_asrep (handle);
  if (las->asreq == NULL)
    {
      shishi_error_printf (handle, "Could not create AS-REP: %s\n",
			   shishi_strerror_details (handle));
      return SHISHI_ASN1_ERROR;
    }

  las->krberror = shishi_krberror (handle);
  if (las->krberror == NULL)
    {
      shishi_error_printf (handle, "Could not create KRB-ERROR: %s\n",
			   shishi_strerror_details (handle));
      return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}

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
shishi_as_req (Shishi_as * as)
{
  return as->asreq;
}

/**
 * shishi_as_req_set:
 * @as: structure that holds information about AS exchange
 * @asreq: asreq to store in AS.
 *
 * Set the AS-REQ in the AP exchange.
 **/
void
shishi_as_req_set (Shishi_as * as, ASN1_TYPE asreq)
{
  if (as->asreq)
    shishi_asn1_done (as->handle, as->asreq);
  as->asreq = asreq;
}

/**
 * shishi_as_rep:
 * @as: structure that holds information about AS exchange
 *
 * Return value: Returns the received AS-REP packet from the AS
 *               exchange, or NULL if not yet set or an error occured.
 **/
ASN1_TYPE
shishi_as_rep (Shishi_as * as)
{
  return as->asrep;
}

/**
 * shishi_as_rep_process:
 * @as: structure that holds information about AS exchange
 *
 * Process new AS-REP and set ticket.  The key is used to decrypt the
 * AP-REP.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_as_rep_process (Shishi_as * as, Shishi_key * key, char *password)
{
  ASN1_TYPE ticket, kdcreppart;
  char user[BUFSIZ];
  int userlen;
  int res;

  if (VERBOSE (as->handle))
    printf ("Processing AS-REQ and AS-REP...\n");

  if (VERBOSEASN1 (as->handle))
    shishi_kdcreq_print (as->handle, stdout, as->asreq);

  if (VERBOSEASN1 (as->handle))
    shishi_kdcrep_print (as->handle, stdout, as->asrep);

  userlen = sizeof (user);
  res = shishi_kdcreq_cnamerealm_get (as->handle, as->asreq, user, &userlen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (as->handle, "Could not extract cname and "
			   "realm from AS-REQ: %s\n", shishi_strerror (res),
			   shishi_strerror_details (as->handle));
      return res;
    }
  user[userlen] = '\0';

  if (key == NULL && password == NULL)
    {
      char password[BUFSIZ];

      res = shishi_prompt_password (as->handle,
				    stdin, password, BUFSIZ,
				    stdout, "Enter password for `%s': ",
				    user);
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (as->handle, "Reading password failed: %s\n",
			       shishi_strerror (res));
	  return res;
	}

      res = shishi_as_process (as->handle, as->asreq, as->asrep,
			       password, &kdcreppart);
    }
  else if (key == NULL)
    res = shishi_as_process (as->handle, as->asreq, as->asrep,
			     password, &kdcreppart);
  else
    res = shishi_kdc_process (as->handle, as->asreq, as->asrep, key,
			      SHISHI_KEYUSAGE_ENCASREPPART, &kdcreppart);
  if (res != SHISHI_OK)
    return res;

  if (VERBOSE (as->handle))
    printf ("Got EncKDCRepPart...\n");

  if (VERBOSEASN1 (as->handle))
    shishi_enckdcreppart_print (as->handle, stdout, kdcreppart);

  res = shishi_kdcrep_get_ticket (as->handle, as->asrep, &ticket);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (as->handle,
			   "Could not extract ticket from AS-REP: %s",
			   shishi_strerror_details (as->handle));
      return res;
    }

  if (VERBOSE (as->handle))
    printf ("Got Ticket...\n");

  if (VERBOSEASN1 (as->handle))
    shishi_asn1ticket_print (as->handle, stdout, ticket);

  as->ticket = shishi_ticket (as->handle, ticket, kdcreppart, as->asrep);
  if (as->ticket == NULL)
    {
      shishi_error_printf (as->handle, "Could not create ticket");
      return SHISHI_MALLOC_ERROR;
    }

  return SHISHI_OK;
}

/**
 * shishi_as_rep_set:
 * @as: structure that holds information about AS exchange
 * @asrep: asrep to store in AS.
 *
 * Set the AS-REP in the AP exchange.
 **/
void
shishi_as_rep_set (Shishi_as * as, ASN1_TYPE asrep)
{
  if (as->asrep)
    shishi_asn1_done (as->handle, as->asrep);
  as->asrep = asrep;
}

/**
 * shishi_as_rep_der_set:
 * @as: structure that holds information about AS exchange
 * @der: input array with DER encoded AP-REP.
 * @derlen: length of input array with DER encoded AP-REP.
 *
 * DER decode AS-REP and set it AS exchange.  If decoding fails, the
 * AS-REP in the AS exchange remains.
 *
 * Return value: Returns SHISHI_OK.
 **/
int
shishi_as_rep_der_set (Shishi_as * as, char *der, int derlen)
{
  ASN1_TYPE asrep;

  asrep = shishi_d2a_asrep (as->handle, der, derlen);

  if (asrep == ASN1_TYPE_EMPTY)
    return SHISHI_ASN1_ERROR;

  as->asrep = asrep;

  return SHISHI_OK;
}

/**
 * shishi_as_get_krberror:
 * @as: structure that holds information about AS exchange
 *
 * Return value: Returns the received KRB-ERROR packet from the AS
 *               exchange, or NULL if not yet set or an error occured.
 **/
ASN1_TYPE
shishi_as_krberror (Shishi_as * as)
{
  return as->krberror;
}

/**
 * shishi_as_krberror_set:
 * @as: structure that holds information about AS exchange
 * @krberror: krberror to store in AS.
 *
 * Set the KRB-ERROR in the AP exchange.
 **/
void
shishi_as_krberror_set (Shishi_as * as, ASN1_TYPE krberror)
{
  if (as->krberror)
    shishi_asn1_done (as->handle, as->krberror);
  as->krberror = krberror;
}

/**
 * shishi_as_get_ticket:
 * @as: structure that holds information about AS exchange
 *
 * Return value: Returns the newly aquired ticket from the AS
 *               exchange, or NULL if not yet set or an error occured.
 **/
Shishi_ticket *
shishi_as_ticket (Shishi_as * as)
{
  return as->ticket;
}

/**
 * shishi_as_ticket_set:
 * @as: structure that holds information about AS exchange
 * @ticket: ticket to store in AS.
 *
 * Set the Ticket in the AP exchange.
 **/
void
shishi_as_ticket_set (Shishi_as * as, Shishi_ticket * ticket)
{
  as->ticket = ticket;
}

/**
 * shishi_as_sendrecv:
 * @as: structure that holds information about AS exchange
 *
 * Send AS-REQ and receive AS-REP or KRB-ERROR.  This is the initial
 * Kerberos 5 authentication, usually used to acquire a Ticket
 * Granting Ticket.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_as_sendrecv (Shishi_as * as)
{
  int res;

  if (VERBOSE (as->handle))
    printf ("Sending AS-REQ...\n");

  if (VERBOSEASN1 (as->handle))
    shishi_kdcreq_print (as->handle, stdout, as->asreq);

  res = shishi_kdcreq_sendrecv (as->handle, as->asreq, &as->asrep);
  if (res == SHISHI_GOT_KRBERROR)
    {
      as->krberror = as->asrep;
      as->asrep = NULL;

      if (VERBOSE (as->handle))
	printf ("Received KRB-ERROR...\n");
      if (VERBOSEASN1 (as->handle))
	shishi_krberror_print (as->handle, stdout, as->krberror);
    }
  if (res != SHISHI_OK)
    return res;

  if (VERBOSE (as->handle))
    printf ("Received AS-REP...\n");

  if (VERBOSEASN1 (as->handle))
    shishi_kdcrep_print (as->handle, stdout, as->asrep);

  return SHISHI_OK;
}
