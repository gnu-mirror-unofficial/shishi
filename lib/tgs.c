/* tgs.c --- High level client TGS functions.
 * Copyright (C) 2002, 2003, 2004, 2006, 2007  Simon Josefsson
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

  *tgs = xcalloc (1, sizeof (**tgs));
  ltgs = *tgs;

  ltgs->handle = handle;

  ltgs->tgsreq = shishi_tgsreq (handle);
  if (ltgs->tgsreq == NULL)
    {
      shishi_error_printf (handle, "Could not create TGS-REQ: %s\n",
			   shishi_error (handle));
      return SHISHI_ASN1_ERROR;
    }

  ltgs->tgsrep = shishi_tgsrep (handle);
  if (ltgs->tgsreq == NULL)
    {
      shishi_error_printf (handle, "Could not create TGS-REP: %s\n",
			   shishi_error (handle));
      return SHISHI_ASN1_ERROR;
    }

  ltgs->krberror = shishi_krberror (handle);
  if (ltgs->krberror == NULL)
    {
      shishi_error_printf (handle, "Could not create KRB-ERROR: %s\n",
			   shishi_error (handle));
      return SHISHI_ASN1_ERROR;
    }

  res = shishi_ap_nosubkey (handle, &ltgs->ap);
  if (res != SHISHI_OK)
    return res;

  res = shishi_authenticator_remove_subkey
    (handle, shishi_ap_authenticator (ltgs->ap));
  if (res != SHISHI_OK)
    return res;

  res = shishi_tkt (handle, &ltgs->tkt);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_tgs_done:
 * @tgs: structure that holds information about AS exchange
 *
 * Deallocate resources associated with TGS exchange.  This should be
 * called by the application when it no longer need to utilize the TGS
 * exchange handle.
 **/
void
shishi_tgs_done (Shishi_tgs * tgs)
{
  shishi_asn1_done (tgs->handle, tgs->tgsreq);
  shishi_asn1_done (tgs->handle, tgs->tgsrep);
  shishi_asn1_done (tgs->handle, tgs->krberror);
  shishi_ap_done (tgs->ap);
  shishi_tkt_done (tgs->tkt);
  free (tgs);
}

/**
 * shishi_tgs_tgtkt:
 * @tgs: structure that holds information about TGS exchange
 *
 * Get Ticket-granting-ticket from TGS exchange.
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
 * Set the Ticket in the TGS exchange.
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
 * Get the AP from TGS exchange.
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
 * Get the TGS-REQ from TGS exchange.
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
 * shishi_tgs_req_set:
 * @tgs: structure that holds information about TGS exchange
 * @tgsreq: tgsreq to store in TGS.
 *
 * Set the TGS-REQ in the TGS exchange.
 **/
void
shishi_tgs_req_set (Shishi_tgs * tgs, Shishi_asn1 tgsreq)
{
  if (tgs->tgsreq)
    shishi_asn1_done (tgs->handle, tgs->tgsreq);
  tgs->tgsreq = tgsreq;
}

/**
 * shishi_tgs_req_der:
 * @tgs: structure that holds information about TGS exchange
 * @out: output array with newly allocated DER encoding of TGS-REQ.
 * @outlen: length of output array with DER encoding of TGS-REQ.
 *
 * DER encode TGS-REQ. @out is allocated by this function, and it is
 * the responsibility of caller to deallocate it.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tgs_req_der (Shishi_tgs * tgs, char **out, size_t * outlen)
{
  int rc;

  rc = shishi_asn1_to_der (tgs->handle, tgs->tgsreq, out, outlen);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_tgs_req_der_set:
 * @tgs: structure that holds information about TGS exchange
 * @der: input array with DER encoded AP-REQ.
 * @derlen: length of input array with DER encoded AP-REQ.
 *
 * DER decode TGS-REQ and set it TGS exchange.  If decoding fails, the
 * TGS-REQ in the TGS exchange remains.
 *
 * Return value: Returns SHISHI_OK.
 **/
int
shishi_tgs_req_der_set (Shishi_tgs * tgs, char *der, size_t derlen)
{
  Shishi_asn1 tgsreq;

  tgsreq = shishi_der2asn1_tgsreq (tgs->handle, der, derlen);

  if (tgsreq == NULL)
    return SHISHI_ASN1_ERROR;

  tgs->tgsreq = tgsreq;

  return SHISHI_OK;
}

/**
 * shishi_tgs_req_process:
 * @tgs: structure that holds information about TGS exchange
 *
 * Process new TGS-REQ and set ticket.  The key to decrypt the TGS-REQ
 * is taken from the EncKDCReqPart of the TGS tgticket.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tgs_req_process (Shishi_tgs * tgs)
{
  Shishi_asn1 apreq;
  int rc;

  if (VERBOSE (tgs->handle))
    printf ("Processing TGS-REQ...\n");

  rc = shishi_kdcreq_get_padata_tgs (tgs->handle, tgs->tgsreq, &apreq);
  if (rc != SHISHI_OK)
    return rc;

  shishi_ap_req_set (tgs->ap, apreq);

  rc = shishi_ap_req_decode (tgs->ap);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
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
  uint32_t apoptions;
  int res;

  if (VERBOSE (tgs->handle))
    printf ("Building TGS-REQ...\n");

  res = shishi_kdcreq_build (tgs->handle, tgs->tgsreq);
  if (res != SHISHI_OK)
    return res;

  res = shishi_apreq_options (tgs->handle, shishi_ap_req (tgs->ap),
			      &apoptions);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (tgs->handle,
			   "Could not get AP-REQ AP-Options: %s\n",
			   shishi_strerror (res));
      return res;
    }

  res = shishi_ap_set_tktoptionsasn1usage
    (tgs->ap, tgs->tgtkt, apoptions, tgs->tgsreq, "req-body",
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
 * Get TGS-REP from TGS exchange.
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
 * shishi_tgs_rep_der:
 * @tgs: structure that holds information about TGS exchange
 * @out: output array with newly allocated DER encoding of TGS-REP.
 * @outlen: length of output array with DER encoding of TGS-REP.
 *
 * DER encode TGS-REP. @out is allocated by this function, and it is
 * the responsibility of caller to deallocate it.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tgs_rep_der (Shishi_tgs * tgs, char **out, size_t * outlen)
{
  int rc;

  rc = shishi_asn1_to_der (tgs->handle, tgs->tgsrep, out, outlen);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
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
			    shishi_ap_authenticator (tgs->ap),
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

  /* XXX */
  tgs->tkt = shishi_tkt2 (tgs->handle, ticket, kdcreppart, tgs->tgsrep);

  return SHISHI_OK;
}

/**
 * shishi_tgs_rep_build:
 * @tgs: structure that holds information about TGS exchange
 * @keyusage: keyusage integer.
 * @key: user's key, used to encrypt the encrypted part of the TGS-REP.
 *
 * Build TGS-REP.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tgs_rep_build (Shishi_tgs * tgs, int keyusage, Shishi_key * key)
{
  int rc;

  /* XXX there are reasons for having padata in TGS-REP */
  rc = shishi_kdcrep_clear_padata (tgs->handle, tgs->tgsrep);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_enckdcreppart_populate_encticketpart
    (tgs->handle, shishi_tkt_enckdcreppart (tgs->tkt),
     shishi_tkt_encticketpart (tgs->tkt));
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_kdc_copy_nonce (tgs->handle, tgs->tgsreq,
			      shishi_tkt_enckdcreppart (tgs->tkt));
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_kdcrep_add_enc_part (tgs->handle,
				   tgs->tgsrep,
				   key, keyusage,
				   shishi_tkt_enckdcreppart (tgs->tkt));
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_kdcrep_set_ticket (tgs->handle, tgs->tgsrep,
				 shishi_tkt_ticket (tgs->tkt));
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_kdc_copy_crealm (tgs->handle, tgs->tgsrep,
			       shishi_tkt_encticketpart (tgs->tkt));
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_kdc_copy_cname (tgs->handle, tgs->tgsrep,
			      shishi_tkt_encticketpart (tgs->tkt));
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_tgs_krberror:
 * @tgs: structure that holds information about TGS exchange
 *
 * Get KRB-ERROR from TGS exchange.
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
 * shishi_tgs_krberror_der:
 * @tgs: structure that holds information about TGS exchange
 * @out: output array with newly allocated DER encoding of KRB-ERROR.
 * @outlen: length of output array with DER encoding of KRB-ERROR.
 *
 * DER encode KRB-ERROR.  @out is allocated by this function, and it is
 * the responsibility of caller to deallocate it.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tgs_krberror_der (Shishi_tgs * tgs, char **out, size_t * outlen)
{
  int rc;

  rc = shishi_krberror_der (tgs->handle, tgs->krberror, out, outlen);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_tgs_krberror_set:
 * @tgs: structure that holds information about TGS exchange
 * @krberror: krberror to store in TGS.
 *
 * Set the KRB-ERROR in the TGS exchange.
 **/
void
shishi_tgs_krberror_set (Shishi_tgs * tgs, Shishi_asn1 krberror)
{
  if (tgs->krberror)
    shishi_asn1_done (tgs->handle, tgs->krberror);
  tgs->krberror = krberror;
}

/**
 * shishi_tgs_tkt:
 * @tgs: structure that holds information about TGS exchange
 *
 * Get Ticket from TGS exchange.
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
 * Set the Ticket in the TGS exchange.
 **/
void
shishi_tgs_tkt_set (Shishi_tgs * tgs, Shishi_tkt * tkt)
{
  tgs->tkt = tkt;
}

/**
 * shishi_tgs_sendrecv_hint:
 * @tgs: structure that holds information about TGS exchange
 * @hint: additional parameters that modify connection behaviour, or %NULL.
 *
 * Send TGS-REQ and receive TGS-REP or KRB-ERROR.  This is the
 * subsequent authentication, usually used to acquire server tickets.
 * The @hint structure can be used to set, e.g., parameters for TLS
 * authentication.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tgs_sendrecv_hint (Shishi_tgs * tgs, Shishi_tkts_hint * hint)
{
  int res;

  if (VERBOSE (tgs->handle))
    printf ("Sending TGS-REQ...\n");

  if (VERBOSEASN1 (tgs->handle))
    shishi_kdcreq_print (tgs->handle, stdout, tgs->tgsreq);

  res = shishi_kdcreq_sendrecv_hint (tgs->handle, tgs->tgsreq,
				     &tgs->tgsrep, hint);
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
 * shishi_tgs_sendrecv:
 * @tgs: structure that holds information about TGS exchange
 *
 * Send TGS-REQ and receive TGS-REP or KRB-ERROR.  This is the
 * subsequent authentication, usually used to acquire server tickets.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tgs_sendrecv (Shishi_tgs * tgs)
{
  return shishi_tgs_sendrecv_hint (tgs, NULL);
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
