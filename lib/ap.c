/* ap.c	AP functions
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

struct Shishi_ap
{
  Shishi *handle;
  Shishi_tkt *tkt;
  Shishi_asn1 authenticator;
  Shishi_asn1 apreq;
  Shishi_asn1 aprep;
  Shishi_asn1 encapreppart;
  int authenticatorcksumkeyusage;
  int authenticatorkeyusage;
  char *authenticatorcksumdata;
  int authenticatorcksumdatalen;
};

/**
 * shishi_ap:
 * @handle: shishi handle as allocated by shishi_init().
 * @ap: pointer to new structure that holds information about AP exchange
 *
 * Create a new AP exchange.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap (Shishi * handle, Shishi_ap ** ap)
{
  Shishi_ap *lap;

  *ap = malloc (sizeof (**ap));
  if (*ap == NULL)
    return SHISHI_MALLOC_ERROR;
  lap = *ap;
  memset (lap, 0, sizeof (*lap));

  lap->handle = handle;
  lap->authenticatorcksumkeyusage = SHISHI_KEYUSAGE_APREQ_AUTHENTICATOR_CKSUM;
  lap->authenticatorkeyusage = SHISHI_KEYUSAGE_APREQ_AUTHENTICATOR;

  lap->authenticator = shishi_authenticator (handle);
  if (lap->authenticator == NULL)
    {
      shishi_error_printf (handle, "Could not create Authenticator: %s\n",
			   shishi_strerror_details (handle));
      return SHISHI_ASN1_ERROR;
    }

  lap->apreq = shishi_apreq (handle);
  if (lap->apreq == NULL)
    {
      shishi_error_printf (handle, "Could not create AP-REQ: %s\n",
			   shishi_strerror_details (handle));
      return SHISHI_ASN1_ERROR;
    }

  lap->aprep = shishi_aprep (handle);
  if (lap->aprep == NULL)
    {
      shishi_error_printf (handle, "Could not create AP-REP: %s\n",
			   shishi_strerror_details (handle));
      return SHISHI_ASN1_ERROR;
    }

  lap->encapreppart = shishi_encapreppart (handle);
  if (lap->encapreppart == NULL)
    {
      shishi_error_printf (handle, "Could not create EncAPRepPart: %s\n",
			   shishi_strerror_details (handle));
      return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}

/**
 * shishi_ap_set_tktoptions:
 * @ap: structure that holds information about AP exchange
 * @tkt: ticket to set in AP.
 * @options: AP-REQ options to set in AP.
 *
 * Set the ticket (see shishi_ap_tkt_set()) and set the AP-REQ
 * apoptions (see shishi_apreq_options_set()).
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_set_tktoptions (Shishi_ap * ap, Shishi_tkt * tkt, int options)
{
  int rc;

  shishi_ap_tkt_set (ap, tkt);

  rc = shishi_apreq_options_set (ap->handle, shishi_ap_req (ap), options);
  if (rc != SHISHI_OK)
    {
      printf ("Could not set AP-Options: %s", shishi_strerror (rc));
      return rc;
    }

  return SHISHI_OK;
}

/**
 * shishi_ap_set_tktoptionsdata:
 * @ap: structure that holds information about AP exchange
 * @tkt: ticket to set in AP.
 * @options: AP-REQ options to set in AP.
 * @data: input array with data to checksum in Authenticator.
 * @len: length of input array with data to checksum in Authenticator.
 *
 * Set the ticket (see shishi_ap_tkt_set()) and set the AP-REQ
 * apoptions (see shishi_apreq_options_set()) and set the
 * Authenticator checksum data.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_set_tktoptionsdata (Shishi_ap * ap,
			      Shishi_tkt * tkt,
			      int options, char *data, int len)
{
  int rc;

  shishi_ap_tkt_set (ap, tkt);

  rc = shishi_apreq_options_set (ap->handle, shishi_ap_req (ap), options);
  if (rc != SHISHI_OK)
    {
      printf ("Could not set AP-Options: %s", shishi_strerror (rc));
      return rc;
    }

  shishi_ap_authenticator_cksumdata_set (ap, data, len);

  return SHISHI_OK;
}

/**
 * shishi_ap_set_tktoptionsasn1:
 * @ap: structure that holds information about AP exchange
 * @tkt: ticket to set in AP.
 * @options: AP-REQ options to set in AP.
 * @node: input ASN.1 structure to store as authenticator checksum data.
 *
 * Set ticket, options and authenticator checksum data using
 * shishi_ap_set_tktoptionsdata().  The authenticator checksum data is
 * the DER encoding of the ASN.1 structure provided.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_set_tktoptionsasn1usage (Shishi_ap * ap,
				   Shishi_tkt * tkt,
				   int options,
				   Shishi_asn1 node,
				   char *field,
				   int authenticatorcksumkeyusage,
				   int authenticatorkeyusage)
{
  char *buf;
  int buflen;
  int res;

  res = shishi_a2d_new_field (ap->handle, node, field, &buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  /* XXX what is this? */
  memmove (buf, buf + 2, buflen - 2);
  buflen -= 2;

  res = shishi_ap_set_tktoptionsdata (ap, tkt, options, buf, buflen);
  if (res != SHISHI_OK)
    return res;

  ap->authenticatorcksumkeyusage = authenticatorcksumkeyusage;
  ap->authenticatorkeyusage = authenticatorkeyusage;

  return SHISHI_OK;
}

/**
 * shishi_ap_tktoptions:
 * @handle: shishi handle as allocated by shishi_init().
 * @ap: pointer to new structure that holds information about AP exchange
 * @tkt: ticket to set in newly created AP.
 * @options: AP-REQ options to set in newly created AP.
 *
 * Create a new AP exchange using shishi_ap(), and set the ticket and
 * AP-REQ apoptions using shishi_ap_set_tktoption().
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_tktoptions (Shishi * handle,
		      Shishi_ap ** ap, Shishi_tkt * tkt, int options)
{
  int rc;

  rc = shishi_ap (handle, ap);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_ap_set_tktoptions (*ap, tkt, options);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_ap_tktoptionsdata:
 * @handle: shishi handle as allocated by shishi_init().
 * @ap: pointer to new structure that holds information about AP exchange
 * @tkt: ticket to set in newly created AP.
 * @options: AP-REQ options to set in newly created AP.
 * @data: input array with data to checksum in Authenticator.
 * @len: length of input array with data to checksum in Authenticator.
 *
 * Create a new AP exchange using shishi_ap(), and set the ticket,
 * AP-REQ apoptions and the Authenticator checksum data using
 * shishi_ap_set_tktoptionsdata().
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_tktoptionsdata (Shishi * handle,
			  Shishi_ap ** ap,
			  Shishi_tkt * tkt, int options, char *data, int len)
{
  int rc;

  rc = shishi_ap (handle, ap);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_ap_set_tktoptionsdata (*ap, tkt, options, data, len);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_ap_tktoptionsasn1:
 * @handle: shishi handle as allocated by shishi_init().
 * @ap: pointer to new structure that holds information about AP exchange
 * @tkt: ticket to set in newly created AP.
 * @options: AP-REQ options to set in newly created AP.
 * @node: input ASN.1 structure to store as authenticator checksum data.
 *
 * Create a new AP exchange using shishi_ap(), and set ticket, options
 * and authenticator checksum data from the DER encoding of the ASN.1
 * field using shishi_ap_set_tktoptionsasn1usage().
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_tktoptionsasn1usage (Shishi * handle,
			       Shishi_ap ** ap,
			       Shishi_tkt * tkt,
			       int options,
			       Shishi_asn1 node,
			       char *field,
			       int authenticatorcksumkeyusage,
			       int authenticatorkeyusage)
{
  int rc;

  rc = shishi_ap (handle, ap);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_ap_set_tktoptionsasn1usage (*ap, tkt, options,
					  node, field,
					  authenticatorcksumkeyusage,
					  authenticatorkeyusage);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_ap_tkt:
 * @ap: structure that holds information about AP exchange
 *
 * Return value: Returns the ticket from the AP exchange, or NULL if
 *               not yet set or an error occured.
 **/
Shishi_tkt *
shishi_ap_tkt (Shishi_ap * ap)
{
  return ap->tkt;
}

/**
 * shishi_ap_tkt_set:
 * @ap: structure that holds information about AP exchange
 * @tkt: ticket to store in AP.
 *
 * Set the Ticket in the AP exchange.
 **/
void
shishi_ap_tkt_set (Shishi_ap * ap, Shishi_tkt * tkt)
{
  ap->tkt = tkt;
}

/**
 * shishi_ap_authenticatorcksumdata:
 * @ap: structure that holds information about AP exchange
 * @out: output array that holds authenticator checksum data.
 * @len: on input, maximum length of output array that holds
 *       authenticator checksum data, on output actual length of
 *       output array that holds authenticator checksum data.
 *
 * Return value: Returns SHISHI_OK if successful, or
 * SHISHI_TOO_SMALL_BUFFER if buffer provided was too small.
 **/
int
shishi_ap_authenticator_cksumdata (Shishi_ap * ap, char *out, int *len)
{
  if (*len < ap->authenticatorcksumdatalen)
    return SHISHI_TOO_SMALL_BUFFER;
  if (ap->authenticatorcksumdata)
    memcpy (out, ap->authenticatorcksumdata, ap->authenticatorcksumdatalen);
  *len = ap->authenticatorcksumdatalen;
  return SHISHI_OK;
}

/**
 * shishi_ap_authenticator_cksumdata_set:
 * @ap: structure that holds information about AP exchange
 * @authenticatorcksumdata: input array with authenticator checksum
 * data to use in AP.
 * @authenticatorcksumdatalen: length of input array with authenticator
 * checksum data to use in AP.
 *
 * Set the Authenticator Checksum Data in the AP exchange.
 **/
void
shishi_ap_authenticator_cksumdata_set (Shishi_ap * ap,
				       char *authenticatorcksumdata,
				       int authenticatorcksumdatalen)
{
  ap->authenticatorcksumdata = authenticatorcksumdata;
  ap->authenticatorcksumdatalen = authenticatorcksumdatalen;
}

/**
 * shishi_ap_authenticator:
 * @ap: structure that holds information about AP exchange
 *
 * Return value: Returns the Authenticator from the AP exchange, or
 *               NULL if not yet set or an error occured.
 **/
Shishi_asn1
shishi_ap_authenticator (Shishi_ap * ap)
{
  return ap->authenticator;
}

/**
 * shishi_ap_authenticator_set:
 * @ap: structure that holds information about AP exchange
 * @authenticator: authenticator to store in AP.
 *
 * Set the Authenticator in the AP exchange.
 **/
void
shishi_ap_authenticator_set (Shishi_ap * ap, Shishi_asn1 authenticator)
{
  if (ap->authenticator)
    shishi_asn1_done (ap->handle, ap->authenticator);
  ap->authenticator = authenticator;
}

/**
 * shishi_ap_req:
 * @ap: structure that holds information about AP exchange
 *
 * Return value: Returns the AP-REQ from the AP exchange, or NULL if
 *               not yet set or an error occured.
 **/
Shishi_asn1
shishi_ap_req (Shishi_ap * ap)
{
  return ap->apreq;
}


/**
 * shishi_ap_req_set:
 * @ap: structure that holds information about AP exchange
 * @apreq: apreq to store in AP.
 *
 * Set the AP-REQ in the AP exchange.
 **/
void
shishi_ap_req_set (Shishi_ap * ap, Shishi_asn1 apreq)
{
  if (ap->apreq)
    shishi_asn1_done (ap->handle, ap->apreq);
  ap->apreq = apreq;
}

/**
 * shishi_ap_req_der:
 * @ap: structure that holds information about AP exchange
 * @out: pointer to output array with der encoding of AP-REQ.
 * @outlen: pointer to length of output array with der encoding of AP-REQ.
 *
 * Build AP-REQ using shishi_ap_req_build() and DER encode it.  @out
 * is allocated by this function, and it is the responsibility of
 * caller to deallocate it.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_req_der (Shishi_ap * ap, char **out, size_t *outlen)
{
  int rc;

  rc = shishi_ap_req_build (ap);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_new_a2d (ap->handle, ap->apreq, out, outlen);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_ap_req_der_set:
 * @ap: structure that holds information about AP exchange
 * @der: input array with DER encoded AP-REQ.
 * @derlen: length of input array with DER encoded AP-REQ.
 *
 * DER decode AP-REQ and set it AP exchange.  If decoding fails, the
 * AP-REQ in the AP exchange is lost.
 *
 * Return value: Returns SHISHI_OK.
 **/
int
shishi_ap_req_der_set (Shishi_ap * ap, char *der, size_t derlen)
{
  ap->apreq = shishi_der2asn1_apreq (ap->handle, der, derlen);

  if (ap->apreq)
    return SHISHI_OK;
  else
    return SHISHI_ASN1_ERROR;
}

/**
 * shishi_ap_req_build:
 * @ap: structure that holds information about AP exchange
 *
 * Checksum data in authenticator and add ticket and authenticator to
 * AP-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_req_build (Shishi_ap * ap)
{
  int res;

  if (VERBOSE (ap->handle))
    printf ("Building AP-REQ...\n");

  res = shishi_apreq_set_ticket (ap->handle, ap->apreq,
				 shishi_tkt_ticket (ap->tkt));
  if (res != SHISHI_OK)
    {
      shishi_error_printf (ap->handle, "Could not set ticket in AP-REQ: %s\n",
			   shishi_strerror_details (ap->handle));
      return res;
    }

  res = shishi_authenticator_add_cksum (ap->handle, ap->authenticator,
					shishi_tkt_key (ap->tkt),
					ap->authenticatorcksumkeyusage,
					ap->authenticatorcksumdata,
					ap->authenticatorcksumdatalen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (ap->handle,
			   "Could not add checksum to authenticator: %s\n",
			   shishi_strerror_details (ap->handle));
      return res;
    }

  if (VERBOSE (ap->handle))
    printf ("Got Authenticator...\n");

  if (VERBOSEASN1 (ap->handle))
    shishi_authenticator_print (ap->handle, stdout, ap->authenticator);

  res = shishi_apreq_add_authenticator (ap->handle, ap->apreq,
					shishi_tkt_key (ap->tkt),
					ap->authenticatorkeyusage,
					ap->authenticator);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (ap->handle, "Could not set authenticator: %s\n",
			   shishi_strerror_details (ap->handle));
      return res;
    }

  if (VERBOSEASN1 (ap->handle))
    shishi_apreq_print (ap->handle, stdout, ap->apreq);

  return SHISHI_OK;
}

/**
 * shishi_ap_req_process:
 * @ap: structure that holds information about AP exchange
 * @key: cryptographic key used to decrypt ticket in AP-REQ.
 *
 * Decrypt ticket in AP-REQ using supplied key and decrypt
 * Authenticator in AP-REQ using key in decrypted ticket, and on
 * success set the Ticket and Authenticator fields in the AP exchange.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_req_process (Shishi_ap * ap, Shishi_key * key)
{
  Shishi_asn1 ticket, authenticator;
  Shishi_tkt *tkt;
  Shishi_key *tktkey;
  int rc;

  if (VERBOSEASN1 (ap->handle))
    shishi_apreq_print (ap->handle, stdout, ap->apreq);

  rc = shishi_apreq_get_ticket (ap->handle, ap->apreq, &ticket);
  if (rc != SHISHI_OK)
    {
      shishi_error_printf (ap->handle,
			   "Could not extract ticket from AP-REQ: %s\n",
			   shishi_strerror (rc));
      return rc;
    }

  if (VERBOSEASN1 (ap->handle))
    shishi_ticket_print (ap->handle, stdout, ticket);

  tkt = shishi_tkt2 (ap->handle, ticket, NULL, NULL);

  rc = shishi_tkt_decrypt (tkt, key);
  if (rc != SHISHI_OK)
    {
      shishi_error_printf (ap->handle, "Error decrypting ticket: %s\n",
			   shishi_strerror (rc));
      return rc;
    }

  rc = shishi_encticketpart_get_key (ap->handle,
				     shishi_tkt_encticketpart (tkt), &tktkey);
  if (rc != SHISHI_OK)
    {
      shishi_error_printf (ap->handle, "Could not get key from ticket: %s\n",
			   shishi_strerror (rc));
      return rc;
    }

  if (VERBOSEASN1 (ap->handle))
    shishi_encticketpart_print (ap->handle, stdout,
				shishi_tkt_encticketpart (tkt));

  rc = shishi_apreq_decrypt (ap->handle, ap->apreq, tktkey, SHISHI_KEYUSAGE_APREQ_AUTHENTICATOR,	/* XXX */
			     &authenticator);
  if (rc != SHISHI_OK)
    {
      shishi_error_printf (ap->handle, "Error decrypting apreq: %s\n",
			   shishi_strerror (rc));
      return rc;
    }

  if (VERBOSEASN1 (ap->handle))
    shishi_authenticator_print (ap->handle, stdout, authenticator);

  ap->tkt = tkt;
  ap->authenticator = authenticator;

  return SHISHI_OK;
}

/**
 * shishi_ap_req_asn1:
 * @ap: structure that holds information about AP exchange
 * @apreq: output AP-REQ variable.
 *
 * Build AP-REQ using shishi_ap_req_build() and return it.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_req_asn1 (Shishi_ap * ap, Shishi_asn1 * apreq)
{
  int rc;

  rc = shishi_ap_req_build (ap);
  if (rc != SHISHI_OK)
    return rc;

  *apreq = ap->apreq;

  return SHISHI_OK;
}

/**
 * shishi_ap_rep:
 * @ap: structure that holds information about AP exchange
 *
 * Return value: Returns the AP-REP from the AP exchange, or NULL if
 *               not yet set or an error occured.
 **/
Shishi_asn1
shishi_ap_rep (Shishi_ap * ap)
{
  return ap->aprep;
}

/**
 * shishi_ap_rep_set:
 * @ap: structure that holds information about AP exchange
 * @aprep: aprep to store in AP.
 *
 * Set the AP-REP in the AP exchange.
 **/
void
shishi_ap_rep_set (Shishi_ap * ap, Shishi_asn1 aprep)
{
  if (ap->aprep)
    shishi_asn1_done (ap->handle, ap->aprep);
  ap->aprep = aprep;
}

/**
 * shishi_ap_rep_der:
 * @ap: structure that holds information about AP exchange
 * @out: output array with newly allocated DER encoding of AP-REP.
 * @outlen: length of output array with DER encoding of AP-REP.
 *
 * Build AP-REQ using shishi_ap_rep_build() and DER encode it.  @out
 * is allocated by this function, and it is the responsibility of
 * caller to deallocate it.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_rep_der (Shishi_ap * ap, char **out, size_t * outlen)
{
  int rc;

  rc = shishi_ap_rep_build (ap);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_new_a2d (ap->handle, ap->aprep, out, outlen);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_ap_rep_der_set:
 * @ap: structure that holds information about AP exchange
 * @der: input array with DER encoded AP-REP.
 * @derlen: length of input array with DER encoded AP-REP.
 *
 * DER decode AP-REP and set it AP exchange.  If decoding fails, the
 * AP-REP in the AP exchange remains.
 *
 * Return value: Returns SHISHI_OK.
 **/
int
shishi_ap_rep_der_set (Shishi_ap * ap, char *der, size_t derlen)
{
  Shishi_asn1 aprep;

  aprep = shishi_der2asn1_aprep (ap->handle, der, derlen);

  if (!aprep)
    return SHISHI_ASN1_ERROR;

  ap->aprep = aprep;

  return SHISHI_OK;
}

/**
 * shishi_ap_rep_build:
 * @ap: structure that holds information about AP exchange
 *
 * Checksum data in authenticator and add ticket and authenticator to
 * AP-REQ.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_rep_build (Shishi_ap * ap)
{
  Shishi_asn1 aprep;
  int rc;

  if (VERBOSE (ap->handle))
    printf ("Building AP-REP...\n");

  aprep = shishi_aprep (ap->handle);
  rc = shishi_aprep_enc_part_make (ap->handle, aprep, ap->authenticator,
				   shishi_tkt_encticketpart (ap->tkt));
  if (rc != SHISHI_OK)
    {
      shishi_error_printf (ap->handle, "Error creating AP-REP: %s\n",
			   shishi_strerror (rc));
      return rc;
    }

  if (VERBOSEASN1 (ap->handle))
    shishi_aprep_print (ap->handle, stdout, aprep);

  shishi_ap_rep_set (ap, aprep);

  return SHISHI_OK;
}

/**
 * shishi_ap_rep_asn1:
 * @ap: structure that holds information about AP exchange
 * @aprep: output AP-REP variable.
 *
 * Build AP-REP using shishi_ap_rep_build() and return it.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_rep_asn1 (Shishi_ap * ap, Shishi_asn1 * aprep)
{
  int rc;

  rc = shishi_ap_rep_build (ap);
  if (rc != SHISHI_OK)
    return rc;

  *aprep = ap->aprep;

  return SHISHI_OK;
}

/**
 * shishi_ap_rep_verify:
 * @ap: structure that holds information about AP exchange
 *
 * Verify AP-REP compared to Authenticator.
 *
 * Return value: Returns SHISHI_OK, SHISHI_APREP_VERIFY_FAILED or an
 * error.
 **/
int
shishi_ap_rep_verify (Shishi_ap * ap)
{
  int res;

  if (VERBOSE (ap->handle))
    printf ("Decrypting AP-REP...\n");

  if (VERBOSEASN1 (ap->handle))
    shishi_aprep_print (ap->handle, stdout, ap->aprep);

  res = shishi_aprep_decrypt (ap->handle, ap->aprep,
			      shishi_tkt_key (ap->tkt),
			      SHISHI_KEYUSAGE_ENCAPREPPART,
			      &ap->encapreppart);
  if (res != SHISHI_OK)
    return res;

  if (VERBOSEASN1 (ap->handle))
    shishi_encapreppart_print (ap->handle, stdout, ap->encapreppart);

  res = shishi_aprep_verify (ap->handle, ap->authenticator, ap->encapreppart);
  if (res != SHISHI_OK)
    return res;

  if (VERBOSE (ap->handle))
    printf ("Verified AP-REP successfully...\n");

  return SHISHI_OK;
}

/**
 * shishi_ap_rep_verify_der:
 * @ap: structure that holds information about AP exchange
 * @der: input array with DER encoded AP-REP.
 * @derlen: length of input array with DER encoded AP-REP.
 *
 * DER decode AP-REP and set it in AP exchange using
 * shishi_ap_rep_der_set() and verify it using shishi_ap_rep_verify().
 *
 * Return value: Returns SHISHI_OK, SHISHI_APREP_VERIFY_FAILED or an
 * error.
 **/
int
shishi_ap_rep_verify_der (Shishi_ap * ap, char *der, size_t derlen)
{
  int res;

  res = shishi_ap_rep_der_set (ap, der, derlen);
  if (res != SHISHI_OK)
    return res;

  res = shishi_ap_rep_verify (ap);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_ap_rep_verify_asn1:
 * @ap: structure that holds information about AP exchange
 * @aprep: input AP-REP.
 *
 * Set the AP-REP in the AP exchange using shishi_ap_rep_set() and
 * verify it using shishi_ap_rep_verify().
 *
 * Return value: Returns SHISHI_OK, SHISHI_APREP_VERIFY_FAILED or an
 * error.
 **/
int
shishi_ap_rep_verify_asn1 (Shishi_ap * ap, Shishi_asn1 aprep)
{
  int res;

  shishi_ap_rep_set (ap, aprep);

  res = shishi_ap_rep_verify (ap);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_ap_rep:
 * @ap: structure that holds information about AP exchange
 *
 * Return value: Returns the EncAPREPPart from the AP exchange, or
 *               NULL if not yet set or an error occured.
 **/
Shishi_asn1
shishi_ap_encapreppart (Shishi_ap * ap)
{
  return ap->encapreppart;
}

/**
 * shishi_ap_encapreppart_set:
 * @ap: structure that holds information about AP exchange
 * @encapreppart: EncAPRepPart to store in AP.
 *
 * Set the EncAPRepPart in the AP exchange.
 **/
void
shishi_ap_encapreppart_set (Shishi_ap * ap, Shishi_asn1 encapreppart)
{
  if (ap->encapreppart)
    shishi_asn1_done (ap->handle, ap->encapreppart);
  ap->encapreppart = encapreppart;
}

#define APOPTION_RESERVED "reserved"
#define APOPTION_USE_SESSION_KEY "use-session-key"
#define APOPTION_MUTUAL_REQUIRED "mutual-required"
#define APOPTION_UNKNOWN "unknown"

const char *
shishi_ap_option2string (int option)
{
  char *str;

  switch (option)
    {
    case SHISHI_APOPTIONS_RESERVED:
      str = APOPTION_RESERVED;
      break;

    case SHISHI_APOPTIONS_USE_SESSION_KEY:
      str = APOPTION_USE_SESSION_KEY;
      break;

    case SHISHI_APOPTIONS_MUTUAL_REQUIRED:
      str = APOPTION_MUTUAL_REQUIRED;
      break;

    default:
      str = APOPTION_UNKNOWN;
      break;
    }

  return str;
}

int
shishi_ap_string2option (const char *str)
{
  int option;

  if (strcasecmp (str, APOPTION_RESERVED) == 0)
    option = SHISHI_APOPTIONS_RESERVED;
  else if (strcasecmp (str, APOPTION_USE_SESSION_KEY) == 0)
    option = SHISHI_APOPTIONS_USE_SESSION_KEY;
  else if (strcasecmp (str, APOPTION_MUTUAL_REQUIRED) == 0)
    option = SHISHI_APOPTIONS_MUTUAL_REQUIRED;
  else
    option = strtol (str, (char **) NULL, 0);

  return option;
}
