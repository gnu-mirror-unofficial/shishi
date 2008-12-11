/* as.c --- High level client AS functions
 * Copyright (C) 2002, 2003, 2004, 2006, 2007, 2008  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify it it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful, but but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#include "internal.h"

struct Shishi_as
{
  Shishi *handle;
  Shishi_asn1 asreq;
  Shishi_asn1 asrep;
  Shishi_asn1 krberror;
  Shishi_tkt *tkt;
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
  int res;

  *as = xmalloc (sizeof (**as));
  las = *as;
  memset (las, 0, sizeof (*las));

  las->handle = handle;

  las->asreq = shishi_asreq (handle);
  if (las->asreq == NULL)
    {
      shishi_error_printf (handle, "Could not create AS-REQ: %s\n",
			   shishi_error (handle));
      return SHISHI_ASN1_ERROR;
    }

  las->asrep = shishi_asrep (handle);
  if (las->asrep == NULL)
    {
      shishi_error_printf (handle, "Could not create AS-REP: %s\n",
			   shishi_error (handle));
      return SHISHI_ASN1_ERROR;
    }

  las->krberror = shishi_krberror (handle);
  if (las->krberror == NULL)
    {
      shishi_error_printf (handle, "Could not create KRB-ERROR: %s\n",
			   shishi_error (handle));
      return SHISHI_ASN1_ERROR;
    }

  res = shishi_tkt (handle, &las->tkt);
  if (res != SHISHI_OK)
    return res;

  res = shishi_tkt_flags_set (las->tkt, SHISHI_TICKETFLAGS_INITIAL);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_as_done:
 * @as: structure that holds information about AS exchange
 *
 * Deallocate resources associated with AS exchange.  This should be
 * called by the application when it no longer need to utilize the AS
 * exchange handle.
 **/
void
shishi_as_done (Shishi_as * as)
{
  shishi_asn1_done (as->handle, as->asreq);
  shishi_asn1_done (as->handle, as->asrep);
  shishi_asn1_done (as->handle, as->krberror);
  shishi_tkt_done (as->tkt);
  free (as);
}

/* TODO: add shishi_as_clientserver(h,p,a,client,server) and make the
   shishi_as_cnamerealmsname function take real cname/sname pointer
   arrays. */

/**
 * shishi_as_req:
 * @as: structure that holds information about AS exchange
 *
 * Get ASN.1 AS-REQ structure from AS exchange.
 *
 * Return value: Returns the generated AS-REQ packet from the AS
 *               exchange, or NULL if not yet set or an error occured.
 **/
Shishi_asn1
shishi_as_req (Shishi_as * as)
{
  return as->asreq;
}

/**
 * shishi_as_req_build:
 * @as: structure that holds information about AS exchange
 *
 * Possibly remove unset fields (e.g., rtime).
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_as_req_build (Shishi_as * as)
{
  int res;

  res = shishi_kdcreq_build (as->handle, as->asreq);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_as_req_set:
 * @as: structure that holds information about AS exchange
 * @asreq: asreq to store in AS.
 *
 * Set the AS-REQ in the AS exchange.
 **/
void
shishi_as_req_set (Shishi_as * as, Shishi_asn1 asreq)
{
  if (as->asreq)
    shishi_asn1_done (as->handle, as->asreq);
  as->asreq = asreq;
}

/**
 * shishi_as_req_der:
 * @as: structure that holds information about AS exchange
 * @out: output array with newly allocated DER encoding of AS-REQ.
 * @outlen: length of output array with DER encoding of AS-REQ.
 *
 * DER encode AS-REQ.  @out is allocated by this function, and it is
 * the responsibility of caller to deallocate it.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_as_req_der (Shishi_as * as, char **out, size_t * outlen)
{
  int rc;

  rc = shishi_asn1_to_der (as->handle, as->asreq, out, outlen);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_as_req_der_set:
 * @as: structure that holds information about AS exchange
 * @der: input array with DER encoded AP-REQ.
 * @derlen: length of input array with DER encoded AP-REQ.
 *
 * DER decode AS-REQ and set it AS exchange.  If decoding fails, the
 * AS-REQ in the AS exchange remains.
 *
 * Return value: Returns SHISHI_OK.
 **/
int
shishi_as_req_der_set (Shishi_as * as, char *der, size_t derlen)
{
  Shishi_asn1 asreq;

  asreq = shishi_der2asn1_asreq (as->handle, der, derlen);

  if (asreq == NULL)
    return SHISHI_ASN1_ERROR;

  as->asreq = asreq;

  return SHISHI_OK;
}

/**
 * shishi_as_rep:
 * @as: structure that holds information about AS exchange
 *
 * Get ASN.1 AS-REP structure from AS exchange.
 *
 * Return value: Returns the received AS-REP packet from the AS
 *               exchange, or NULL if not yet set or an error occured.
 **/
Shishi_asn1
shishi_as_rep (Shishi_as * as)
{
  return as->asrep;
}

/**
 * shishi_as_rep_process:
 * @as: structure that holds information about AS exchange
 * @key: user's key, used to encrypt the encrypted part of the AS-REP.
 * @password: user's password, used if key is NULL.
 *
 * Process new AS-REP and set ticket.  The key is used to decrypt the
 * AP-REP.  If both key and password is NULL, the user is queried for
 * it.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_as_rep_process (Shishi_as * as, Shishi_key * key, const char *password)
{
  Shishi_asn1 ticket, kdcreppart;
  int res;

  if (VERBOSE (as->handle))
    printf ("Processing AS-REQ and AS-REP...\n");

  if (VERBOSEASN1 (as->handle))
    shishi_kdcreq_print (as->handle, stdout, as->asreq);

  if (VERBOSEASN1 (as->handle))
    shishi_kdcrep_print (as->handle, stdout, as->asrep);

  if (key == NULL && password == NULL)
    {
      char *passwd;
      char *user;
      size_t userlen;

      res = shishi_asreq_clientrealm (as->handle, as->asreq, &user, &userlen);
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (as->handle, "Could not extract cname and "
			       "realm from AS-REQ: %s\n",
			       shishi_strerror (res));
	  return res;
	}

      res = shishi_prompt_password (as->handle, &passwd,
				    "Enter password for `%s': ", user);
      free (user);
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (as->handle, "Reading password failed: %s\n",
			       shishi_strerror (res));
	  return res;
	}

      res = shishi_as_process (as->handle, as->asreq, as->asrep,
			       passwd, &kdcreppart);
      free (passwd);
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
			   shishi_error (as->handle));
      return res;
    }

  if (VERBOSE (as->handle))
    printf ("Got Ticket...\n");

  if (VERBOSEASN1 (as->handle))
    shishi_ticket_print (as->handle, stdout, ticket);

  /* XXX */
  as->tkt = shishi_tkt2 (as->handle, ticket, kdcreppart, as->asrep);

  return SHISHI_OK;
}

/**
 * shishi_as_rep_build:
 * @as: structure that holds information about AS exchange
 * @key: user's key, used to encrypt the encrypted part of the AS-REP.
 *
 * Build AS-REP.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_as_rep_build (Shishi_as * as, Shishi_key * key)
{
  int rc;

  /* XXX there are reasons for having padata in AS-REP */
  rc = shishi_kdcrep_clear_padata (as->handle, as->asrep);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_enckdcreppart_populate_encticketpart
    (as->handle, shishi_tkt_enckdcreppart (as->tkt),
     shishi_tkt_encticketpart (as->tkt));
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_kdc_copy_nonce (as->handle, as->asreq,
			      shishi_tkt_enckdcreppart (as->tkt));
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_kdcrep_add_enc_part (as->handle,
				   as->asrep,
				   key,
				   SHISHI_KEYUSAGE_ENCASREPPART,
				   shishi_tkt_enckdcreppart (as->tkt));
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_kdcrep_set_ticket (as->handle, as->asrep,
				 shishi_tkt_ticket (as->tkt));
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_kdc_copy_crealm (as->handle, as->asrep,
			       shishi_tkt_encticketpart (as->tkt));
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_kdc_copy_cname (as->handle, as->asrep,
			      shishi_tkt_encticketpart (as->tkt));
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_as_rep_der:
 * @as: structure that holds information about AS exchange
 * @out: output array with newly allocated DER encoding of AS-REP.
 * @outlen: length of output array with DER encoding of AS-REP.
 *
 * DER encode AS-REP. @out is allocated by this function, and it is
 * the responsibility of caller to deallocate it.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_as_rep_der (Shishi_as * as, char **out, size_t * outlen)
{
  int rc;

  rc = shishi_asn1_to_der (as->handle, as->asrep, out, outlen);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_as_rep_set:
 * @as: structure that holds information about AS exchange
 * @asrep: asrep to store in AS.
 *
 * Set the AS-REP in the AS exchange.
 **/
void
shishi_as_rep_set (Shishi_as * as, Shishi_asn1 asrep)
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
shishi_as_rep_der_set (Shishi_as * as, char *der, size_t derlen)
{
  Shishi_asn1 asrep;

  asrep = shishi_der2asn1_asrep (as->handle, der, derlen);

  if (asrep == NULL)
    return SHISHI_ASN1_ERROR;

  as->asrep = asrep;

  return SHISHI_OK;
}

/**
 * shishi_as_krberror:
 * @as: structure that holds information about AS exchange
 *
 * Get ASN.1 KRB-ERROR structure from AS exchange.
 *
 * Return value: Returns the received KRB-ERROR packet from the AS
 *               exchange, or NULL if not yet set or an error occured.
 **/
Shishi_asn1
shishi_as_krberror (Shishi_as * as)
{
  return as->krberror;
}

/**
 * shishi_as_krberror_der:
 * @as: structure that holds information about AS exchange
 * @out: output array with newly allocated DER encoding of KRB-ERROR.
 * @outlen: length of output array with DER encoding of KRB-ERROR.
 *
 * DER encode KRB-ERROR. @out is allocated by this function, and it is
 * the responsibility of caller to deallocate it.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_as_krberror_der (Shishi_as * as, char **out, size_t * outlen)
{
  int rc;

  rc = shishi_krberror_der (as->handle, as->krberror, out, outlen);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_as_krberror_set:
 * @as: structure that holds information about AS exchange
 * @krberror: krberror to store in AS.
 *
 * Set the KRB-ERROR in the AS exchange.
 **/
void
shishi_as_krberror_set (Shishi_as * as, Shishi_asn1 krberror)
{
  if (as->krberror)
    shishi_asn1_done (as->handle, as->krberror);
  as->krberror = krberror;
}

/**
 * shishi_as_tkt:
 * @as: structure that holds information about AS exchange
 *
 * Get Ticket in AS exchange.
 *
 * Return value: Returns the newly aquired tkt from the AS
 *               exchange, or NULL if not yet set or an error occured.
 **/
Shishi_tkt *
shishi_as_tkt (Shishi_as * as)
{
  return as->tkt;
}

/**
 * shishi_as_tkt_set:
 * @as: structure that holds information about AS exchange
 * @tkt: tkt to store in AS.
 *
 * Set the Tkt in the AS exchange.
 **/
void
shishi_as_tkt_set (Shishi_as * as, Shishi_tkt * tkt)
{
  as->tkt = tkt;
}

/**
 * shishi_as_sendrecv_hint:
 * @as: structure that holds information about AS exchange
 * @hint: additional parameters that modify connection behaviour, or %NULL.
 *
 * Send AS-REQ and receive AS-REP or KRB-ERROR.  This is the initial
 * authentication, usually used to acquire a Ticket Granting Ticket.
 * The @hint structure can be used to set, e.g., parameters for TLS
 * authentication.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_as_sendrecv_hint (Shishi_as * as, Shishi_tkts_hint * hint)
{
  int res;

  if (VERBOSE (as->handle))
    printf ("Sending AS-REQ...\n");

  if (VERBOSEASN1 (as->handle))
    shishi_kdcreq_print (as->handle, stdout, as->asreq);

  res = shishi_kdcreq_sendrecv_hint (as->handle, as->asreq, &as->asrep, hint);
  if (res == SHISHI_GOT_KRBERROR)
    {
      as->krberror = as->asrep;
      as->asrep = NULL;

      if (VERBOSE (as->handle))
	printf ("Received KRB-ERROR...\n");
      if (VERBOSEASN1 (as->handle))
	shishi_krberror_print (as->handle, stdout, as->krberror);
      if (VERBOSEASN1(as->handle))
	shishi_krberror_pretty_print (as->handle, stdout, as->krberror);
    }
  if (res != SHISHI_OK)
    return res;

  if (VERBOSE (as->handle))
    printf ("Received AS-REP...\n");

  if (VERBOSEASN1 (as->handle))
    shishi_kdcrep_print (as->handle, stdout, as->asrep);

  return SHISHI_OK;
}

/**
 * shishi_as_sendrecv:
 * @as: structure that holds information about AS exchange
 *
 * Send AS-REQ and receive AS-REP or KRB-ERROR.  This is the initial
 * authentication, usually used to acquire a Ticket Granting Ticket.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_as_sendrecv (Shishi_as * as)
{
  return shishi_as_sendrecv_hint (as, NULL);
}
