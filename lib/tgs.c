/* tgs.c	High level client TGS functions
 * Copyright (C) 2002  Simon Josefsson
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
  ASN1_TYPE tgsreq;
  Shishi_ticket *tgticket;
  Shishi_ap *ap;
  ASN1_TYPE tgsrep;
  ASN1_TYPE krberror;
  Shishi_ticket *ticket;
};

/**
 * shishi_tgs_get_tgsreq:
 * @tgs: structure that holds information about TGS exchange
 *
 * Return value: Returns the generated TGS-REQ from the TGS exchange,
 *               or NULL if not yet set or an error occured.
 **/
ASN1_TYPE
shishi_tgs_get_tgsreq (Shishi_tgs * tgs)
{
  return tgs->tgsreq;
}

/**
 * shishi_tgs_get_tgticket:
 * @tgs: structure that holds information about TGS exchange
 *
 * Return value: Returns the ticket-granting-ticket used in the TGS
 *               exchange, or NULL if not yet set or an error occured.
 **/
Shishi_ticket *
shishi_tgs_get_tgticket (Shishi_tgs * tgs)
{
  return tgs->tgticket;
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
 * shishi_tgs_get_tgsrep:
 * @tgs: structure that holds information about TGS exchange
 *
 * Return value: Returns the received TGS-REP from the TGS exchange,
 *               or NULL if not yet set or an error occured.
 **/
ASN1_TYPE
shishi_tgs_get_tgsrep (Shishi_tgs * tgs)
{
  return tgs->tgsrep;
}

/**
 * shishi_tgs_get_krberror:
 * @tgs: structure that holds information about TGS exchange
 *
 * Return value: Returns the received TGS-REP from the TGS exchange,
 *               or NULL if not yet set or an error occured.
 **/
ASN1_TYPE
shishi_tgs_get_krberror (Shishi_tgs * tgs)
{
  return tgs->krberror;
}

/**
 * shishi_tgs_get_ticket:
 * @tgs: structure that holds information about TGS exchange
 *
 * Return value: Returns the newly aquired ticket from the TGS
 *               exchange, or NULL if not yet set or an error occured.
 **/
Shishi_ticket *
shishi_tgs_get_ticket (Shishi_tgs * tgs)
{
  return tgs->ticket;
}

/**
 * shishi_tgs:
 * @handle: shishi handle as allocated by shishi_init().
 * @tgticket: ticket-granting-ticket, used to authenticate the request.
 * @tgs: holds pointer to newly allocate Shishi_tgs structure.
 * @server: indicates the server to acquire ticket for.
 *
 * Perform subsequent Kerberos 5 authentication, in order to acquire a
 * ticket for a server.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tgs (Shishi * handle,
	    Shishi_ticket * tgticket, Shishi_tgs ** tgs, char *server)
{
  /* XXX parse server into realm + sname */
  return shishi_tgs_realmsname (handle, tgticket, tgs,
				shishi_realm_default (handle), server);
}

int
shishi_tgs_realmsname (Shishi * handle,
		       Shishi_ticket * tgticket,
		       Shishi_tgs ** tgs, char *realm, char *sname)
{
  ASN1_TYPE ticket, kdcreppart, apreq;
  int res;

  *tgs = malloc (sizeof (**tgs));
  if (*tgs == NULL)
    return SHISHI_MALLOC_ERROR;

  (*tgs)->tgsreq = shishi_tgsreq (handle);
  if ((*tgs)->tgsreq == ASN1_TYPE_EMPTY)
    return SHISHI_ASN1_ERROR;

  res = shishi_kdcreq_set_realmserver (handle, (*tgs)->tgsreq, realm, sname);
  if (res != SHISHI_OK)
    {
      fprintf (stderr, _("Could not set realm and server in KDC-REQ: %s\n"),
	       shishi_strerror (res));
      goto done;
    }

  res = shishi_ap_tktoptionsasn1usage
    (handle, &(*tgs)->ap, tgticket, 0, (*tgs)->tgsreq, "KDC-REQ.req-body",
     SHISHI_KEYUSAGE_TGSREQ_APREQ_AUTHENTICATOR_CKSUM,
     SHISHI_KEYUSAGE_TGSREQ_APREQ_AUTHENTICATOR);
  if (res == SHISHI_OK)
    res = shishi_ap_req_asn1((*tgs)->ap, &apreq);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not make AP-REQ: %s\n",
			   shishi_strerror_details (handle));
      goto done;
    }

  res = shishi_kdcreq_add_padata_tgs (handle, (*tgs)->tgsreq, apreq);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not add padata to TGS: %s\n",
			   shishi_strerror_details (handle));
      goto done;
    }

  res = shishi_kdcreq_sendrecv (handle, (*tgs)->tgsreq, &(*tgs)->tgsrep);
  if (res == SHISHI_GOT_KRBERROR)
    {
      (*tgs)->krberror = (*tgs)->tgsrep;
      (*tgs)->tgsrep = NULL;
    }
  if (res != SHISHI_OK)
    goto done;

  res = shishi_tgs_process (handle, (*tgs)->tgsreq, (*tgs)->tgsrep,
			    shishi_ticket_enckdcreppart (tgticket),
			    &kdcreppart);
  if (res != SHISHI_OK)
    goto done;

  res = shishi_kdcrep_get_ticket (handle, (*tgs)->tgsrep, &ticket);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle,
			   "Could not extract ticket from TGS-REP: %s",
			   shishi_strerror_details (handle));
      return res;
    }

  (*tgs)->ticket =
    shishi_ticket (handle,
		   strdup (shishi_ticket_principal (tgticket)),
		   ticket, kdcreppart);
  if ((*tgs)->ticket == NULL)
    {
      shishi_error_printf (handle, "Could not create ticket");
      return SHISHI_MALLOC_ERROR;
    }

  return SHISHI_OK;

done:
  free (*tgs);
  return res;
}
