/* tgs.c	High level client TGS functions
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

/* TODO: make shishi_tgs_realmsname() take real sname pointer
   array. */

#include "internal.h"

struct Shishi_tgs
{
  Shishi *handle;
  Shishi_asn1 tgsreq;
  Shishi_tkt *tgtkt;
  Shishi_ap *ap;
  Shishi_asn1 tgsrep;
  Shishi_asn1 krberror;
  Shishi_tkt *tkt;
};

/**
 * shishi_tgs:
 * @handle: shishi handle as allocated by shishi_init().
 * @tgs: holds pointer to newly allocate Shishi_tgs structure.
 *
 * Allocate a new TGS exchange variable.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tgs (Shishi * handle, Shishi_tgs ** tgs)
{
  Shishi_tgs *ltgs;
  int res;

  *tgs = malloc (sizeof (**tgs));
  if (*tgs == NULL)
    return SHISHI_MALLOC_ERROR;
  ltgs = *tgs;
  memset (ltgs, 0, sizeof (*ltgs));

  ltgs->handle = handle;

  ltgs->tgsreq = shishi_tgsreq (handle);
  if (ltgs->tgsreq == NULL)
    {
      shishi_error_printf (handle, "Could not create TGS-REQ: %s\n",
			   shishi_strerror_details (handle));
      return SHISHI_ASN1_ERROR;
    }

  ltgs->tgsrep = shishi_tgsrep (handle);
  if (ltgs->tgsreq == NULL)
    {
      shishi_error_printf (handle, "Could not create TGS-REP: %s\n",
			   shishi_strerror_details (handle));
      return SHISHI_ASN1_ERROR;
    }

  ltgs->krberror = shishi_krberror (handle);
  if (ltgs->krberror == NULL)
    {
      shishi_error_printf (handle, "Could not create KRB-ERROR: %s\n",
			   shishi_strerror_details (handle));
      return SHISHI_ASN1_ERROR;
    }

  res = shishi_ap (handle, &ltgs->ap);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_tgs_tgtkt:
 * @tgs: structure that holds information about TGS exchange
 *
 * Return value: Returns the ticket-granting-ticket used in the TGS
 *               exchange, or NULL if not yet set or an error occured.
 **/
Shishi_tkt *
shishi_tgs_tgtkt (Shishi_tgs * tgs)
{
  return tgs->tgtkt;
}

/**
 * shishi_tgs_tgtkt_set:
 * @tgs: structure that holds information about TGS exchange
 * @tgtkt: ticket granting ticket to store in TGS.
 *
 * Set the Ticket in the AP exchange.
 **/
void
shishi_tgs_tgtkt_set (Shishi_tgs * tgs, Shishi_tkt * tgtkt)
{
  tgs->tgtkt = tgtkt;
}

/**
 * shishi_tgs_ap:
 * @tgs: structure that holds information about TGS exchange
 *
 * Return value: Returns the AP exchange (part of TGS-REQ) from the
 *               TGS exchange, or NULL if not yet set or an error
 *               occured.
 **/
Shishi_ap *
shishi_tgs_ap (Shishi_tgs * tgs)
{
  return tgs->ap;
}

/**
 * shishi_tgs_req:
 * @tgs: structure that holds information about TGS exchange
 *
 * Return value: Returns the generated TGS-REQ from the TGS exchange,
 *               or NULL if not yet set or an error occured.
 **/
Shishi_asn1
shishi_tgs_req (Shishi_tgs * tgs)
{
  return tgs->tgsreq;
}

/**
 * shishi_tgs_req_build:
 * @tgs: structure that holds information about TGS exchange
 *
 * Checksum data in authenticator and add ticket and authenticator to
 * TGS-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tgs_req_build (Shishi_tgs * tgs)
{
  int res;
  int apoptions;

  if (VERBOSE (tgs->handle))
    printf ("Building TGS-REQ...\n");

  res =
    shishi_apreq_options (tgs->handle, shishi_ap_req (tgs->ap), &apoptions);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (tgs->handle,
			   "Could not get AP-REQ AP-Options: %s\n",
			   shishi_strerror (res));
      return res;
    }

  res = shishi_ap_set_tktoptionsasn1usage
    (tgs->ap, tgs->tgtkt, apoptions, tgs->tgsreq, "KDC-REQ.req-body",
     SHISHI_KEYUSAGE_TGSREQ_APREQ_AUTHENTICATOR_CKSUM,
     SHISHI_KEYUSAGE_TGSREQ_APREQ_AUTHENTICATOR);
  if (res == SHISHI_OK)
    res = shishi_ap_req_build (tgs->ap);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (tgs->handle, "Could not make AP-REQ: %s\n",
			   shishi_strerror (res));
      return res;
    }


  if (VERBOSE (tgs->handle))
    printf ("Got AP-REQ...\n");

  if (VERBOSEASN1 (tgs->handle))
    shishi_apreq_print (tgs->handle, stdout, shishi_ap_req (tgs->ap));

  res = shishi_kdcreq_add_padata_tgs (tgs->handle, tgs->tgsreq,
				      shishi_ap_req (tgs->ap));
  if (res != SHISHI_OK)
    {
      shishi_error_printf (tgs->handle, "Could not add AP-REQ to TGS: %s\n",
			   shishi_strerror (res));
      return res;
    }

  return SHISHI_OK;
}

/**
 * shishi_tgs_rep:
 * @tgs: structure that holds information about TGS exchange
 *
 * Return value: Returns the received TGS-REP from the TGS exchange,
 *               or NULL if not yet set or an error occured.
 **/
Shishi_asn1
shishi_tgs_rep (Shishi_tgs * tgs)
{
  return tgs->tgsrep;
}

/**
 * shishi_tgs_rep_process:
 * @tgs: structure that holds information about TGS exchange
 *
 * Process new TGS-REP and set ticket.  The key to decrypt the TGS-REP
 * is taken from the EncKDCRepPart of the TGS tgticket.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tgs_rep_process (Shishi_tgs * tgs)
{
  Shishi_asn1 kdcreppart, ticket;
  int res;

  if (VERBOSE (tgs->handle))
    printf ("Processing TGS-REQ and TGS-REP...\n");

  res = shishi_tgs_process (tgs->handle, tgs->tgsreq, tgs->tgsrep,
			    shishi_tkt_enckdcreppart (tgs->tgtkt),
			    &kdcreppart);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (tgs->handle, "Could not process TGS: %s",
			   shishi_strerror (res));
      return res;
    }

  if (VERBOSE (tgs->handle))
    printf ("Got EncKDCRepPart...\n");

  if (VERBOSEASN1 (tgs->handle))
    shishi_enckdcreppart_print (tgs->handle, stdout, kdcreppart);

  res = shishi_kdcrep_get_ticket (tgs->handle, tgs->tgsrep, &ticket);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (tgs->handle,
			   "Could not extract ticket from TGS-REP: %s",
			   shishi_strerror (res));
      return res;
    }

  if (VERBOSE (tgs->handle))
    printf ("Got Ticket...\n");

  if (VERBOSEASN1 (tgs->handle))
    shishi_ticket_print (tgs->handle, stdout, ticket);

  tgs->tkt = shishi_tkt2 (tgs->handle, ticket, kdcreppart, tgs->tgsrep);
  if (tgs->tkt == NULL)
    {
      shishi_error_printf (tgs->handle, "Could not create ticket");
      return SHISHI_MALLOC_ERROR;
    }

  return SHISHI_OK;
}

/**
 * shishi_tgs_krberror:
 * @tgs: structure that holds information about TGS exchange
 *
 * Return value: Returns the received TGS-REP from the TGS exchange,
 *               or NULL if not yet set or an error occured.
 **/
Shishi_asn1
shishi_tgs_krberror (Shishi_tgs * tgs)
{
  return tgs->krberror;
}

/**
 * shishi_tgs_tkt:
 * @tgs: structure that holds information about TGS exchange
 *
 * Return value: Returns the newly aquired ticket from the TGS
 *               exchange, or NULL if not yet set or an error occured.
 **/
Shishi_tkt *
shishi_tgs_tkt (Shishi_tgs * tgs)
{
  return tgs->tkt;
}

/**
 * shishi_tgs_tkt_set:
 * @tgs: structure that holds information about TGS exchange
 * @tkt: ticket to store in TGS.
 *
 * Set the Ticket in the AP exchange.
 **/
void
shishi_tgs_tkt_set (Shishi_tgs * tgs, Shishi_tkt * tkt)
{
  tgs->tkt = tkt;
}

/**
 * shishi_tgs_sendrecv:
 * @tgs: structure that holds information about TGS exchange
 *
 * Send TGS-REQ and receive TGS-REP or KRB-ERROR.  This is the initial
 * Kerberos 5 authentication, usually used to acquire a Ticket
 * Granting Ticket.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tgs_sendrecv (Shishi_tgs * tgs)
{
  int res;

  if (VERBOSE (tgs->handle))
    printf ("Sending TGS-REQ...\n");

  if (VERBOSEASN1 (tgs->handle))
    shishi_kdcreq_print (tgs->handle, stdout, tgs->tgsreq);

  res = shishi_kdcreq_sendrecv (tgs->handle, tgs->tgsreq, &tgs->tgsrep);
  if (res == SHISHI_GOT_KRBERROR)
    {
      tgs->krberror = tgs->tgsrep;
      tgs->tgsrep = NULL;

      if (VERBOSE (tgs->handle))
	printf ("Received KRB-ERROR...\n");
      if (VERBOSEASN1 (tgs->handle))
	shishi_krberror_print (tgs->handle, stdout, tgs->krberror);
    }
  if (res != SHISHI_OK)
    return res;


  if (VERBOSE (tgs->handle))
    printf ("Received TGS-REP...\n");

  if (VERBOSEASN1 (tgs->handle))
    shishi_kdcrep_print (tgs->handle, stdout, tgs->tgsrep);

  return SHISHI_OK;
}

/**
 * shishi_tgs_set_server:
 * @tgs: structure that holds information about TGS exchange
 * @server: indicates the server to acquire ticket for.
 *
 * Set the server in the TGS-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tgs_set_server (Shishi_tgs * tgs, const char *server)
{
  int res;

  res = shishi_kdcreq_set_server (tgs->handle, tgs->tgsreq, server);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (tgs->handle,
			   "Could not set server in KDC-REQ: %s\n",
			   shishi_strerror (res));
      return res;
    }

  return SHISHI_OK;
}

/**
 * shishi_tgs_set_realm:
 * @tgs: structure that holds information about TGS exchange
 * @realm: indicates the realm to acquire ticket for.
 *
 * Set the server in the TGS-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tgs_set_realm (Shishi_tgs * tgs, const char *realm)
{
  int res;

  res = shishi_kdcreq_set_realm (tgs->handle, tgs->tgsreq, realm);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (tgs->handle,
			   "Could not set realm in KDC-REQ: %s\n",
			   shishi_strerror (res));
      return res;
    }

  return SHISHI_OK;
}

/**
 * shishi_tgs_set_realmserver:
 * @tgs: structure that holds information about TGS exchange
 * @realm: indicates the realm to acquire ticket for.
 * @server: indicates the server to acquire ticket for.
 *
 * Set the realm and server in the TGS-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tgs_set_realmserver (Shishi_tgs * tgs,
			    const char *realm, const char *server)
{
  int res;

  res = shishi_tgs_set_server (tgs, server);
  if (res != SHISHI_OK)
    return res;

  res = shishi_tgs_set_realm (tgs, realm);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}
