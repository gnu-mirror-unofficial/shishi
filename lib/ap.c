/* ap.c	AP functions
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

#include "internal.h"

struct Shishi_ap
{
  Shishi *handle;
  Shishi_ticket *ticket;
  ASN1_TYPE authenticator;
  ASN1_TYPE apreq;
  ASN1_TYPE aprep;
  ASN1_TYPE encapreppart;
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
  memset(lap, 0, sizeof(*lap));

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
 * shishi_ap_tktoptions:
 * @handle: shishi handle as allocated by shishi_init().
 * @ap: pointer to new structure that holds information about AP exchange
 * @ticket: ticket to set in newly created AP.
 * @options: AP-REQ options to set in newly created AP.
 *
 * Create a new AP exchange, and set the ticket (see
 * shishi_ap_ticket_set()) and set the AP-REQ apoptions (see
 * shishi_apreq_options_set()).
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_tktoptions (Shishi * handle,
		      Shishi_ap ** ap,
		      Shishi_ticket *ticket,
		      int options)
{
  int rc;

  rc = shishi_ap(handle, ap);
  if (rc != SHISHI_OK)
    return rc;

  shishi_ap_ticket_set (*ap, ticket);

  rc = shishi_apreq_options_set (handle, shishi_ap_req(*ap), options);
  if (rc != SHISHI_OK)
    {
      printf ("Could not set AP-Options: %s", shishi_strerror (rc));
      return rc;
    }

  return SHISHI_OK;
}

/**
 * shishi_ap_tktoptionsdata:
 * @handle: shishi handle as allocated by shishi_init().
 * @ap: pointer to new structure that holds information about AP exchange
 * @ticket: ticket to set in newly created AP.
 * @options: AP-REQ options to set in newly created AP.
 * @data: input array with data to checksum in Authenticator.
 * @len: length of input array with data to checksum in Authenticator.
 *
 * Create a new AP exchange, and set the ticket (see
 * shishi_ap_ticket_set()) and set the AP-REQ apoptions (see
 * shishi_apreq_options_set()) and set the Authenticator checksum
 * data.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_tktoptionsdata (Shishi * handle,
			  Shishi_ap ** ap,
			  Shishi_ticket *ticket,
			  int options,
			  char *data,
			  int len)
{
  int rc;

  rc = shishi_ap(handle, ap);
  if (rc != SHISHI_OK)
    return rc;

  shishi_ap_ticket_set (*ap, ticket);

  rc = shishi_apreq_options_set (handle, shishi_ap_req(*ap), options);
  if (rc != SHISHI_OK)
    {
      printf ("Could not set AP-Options: %s", shishi_strerror (rc));
      return rc;
    }

  shishi_ap_authenticator_cksumdata_set (*ap, data, len);

  return SHISHI_OK;
}

/**
 * shishi_ap_tktoptionsasn1:
 * @handle: shishi handle as allocated by shishi_init().
 * @ap: pointer to new structure that holds information about AP exchange
 * @ticket: ticket to set in newly created AP.
 * @options: AP-REQ options to set in newly created AP.
 * @node: input ASN.1 structure to store as authenticator checksum data.
 *
 * DER decode ASN.1 structure and allocate new AP exchange and set
 * ticket, options and authenticator checksum data using
 * shishi_ap_tktoptionsdata().
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_tktoptionsasn1usage (Shishi * handle,
			       Shishi_ap ** ap,
			       Shishi_ticket *ticket,
			       int options,
			       ASN1_TYPE node,
			       char *field,
			       int authenticatorcksumkeyusage,
			       int authenticatorkeyusage)
{
  char *buf;
  int buflen;
  int res;

  buf = malloc(BUFSIZ);
  buflen = BUFSIZ;

  res = _shishi_a2d_field (handle, node, field, buf, &buflen);
  if (res != SHISHI_OK)
    return res;

  /* XXX what is this? */
  memmove (buf, buf + 2, buflen - 2);
  buflen -= 2;

  res = shishi_ap_tktoptionsdata(handle, ap, ticket, options, buf, buflen);
  if (res != SHISHI_OK)
    return res;

  (*ap)->authenticatorcksumkeyusage = authenticatorcksumkeyusage;
  (*ap)->authenticatorkeyusage = authenticatorkeyusage;

  return SHISHI_OK;
}

/**
 * shishi_ap_ticket:
 * @ap: structure that holds information about AP exchange
 *
 * Return value: Returns the ticket from the AP exchange, or NULL if
 *               not yet set or an error occured.
 **/
Shishi_ticket *
shishi_ap_ticket (Shishi_ap * ap)
{
  return ap->ticket;
}

/**
 * shishi_ap_ticket_set:
 * @ap: structure that holds information about AP exchange
 * @ticket: ticket to store in AP.
 *
 * Set the Ticket in the AP exchange.
 **/
void
shishi_ap_ticket_set (Shishi_ap * ap, Shishi_ticket * ticket)
{
  ap->ticket = ticket;
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
  if(ap->authenticatorcksumdata)
    memcpy(out, ap->authenticatorcksumdata, ap->authenticatorcksumdatalen);
  *len = ap->authenticatorcksumdatalen;
  return SHISHI_OK;
}

/**
 * shishi_ap_authenticator_cksumdata_set:
 * @ap: structure that holds information about AP exchange
 * @authenticatorcksumdata: input array with authenticator checksum
 * data to use in AP.
 * @authenticatorcksumdata: length of input array with authenticator
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
ASN1_TYPE
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
shishi_ap_authenticator_set (Shishi_ap * ap, ASN1_TYPE authenticator)
{
  if (ap->authenticator)
    _shishi_asn1_done(ap->handle, ap->authenticator);
  ap->authenticator = authenticator;
}

/**
 * shishi_ap_req:
 * @ap: structure that holds information about AP exchange
 *
 * Return value: Returns the AP-REQ from the AP exchange, or NULL if
 *               not yet set or an error occured.
 **/
ASN1_TYPE
shishi_ap_req (Shishi_ap * ap)
{
  return ap->apreq;
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

  res = shishi_apreq_set_ticket (ap->handle, ap->apreq,
				 shishi_ticket_ticket(ap->ticket));
  if (res != SHISHI_OK)
    {
      shishi_error_printf (ap->handle, "Could not set ticket in AP-REQ: %s\n",
			   shishi_strerror_details (ap->handle));
      return res;
    }

  res = shishi_authenticator_add_cksum (ap->handle, ap->authenticator,
					shishi_ticket_key(ap->ticket),
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

  res = shishi_apreq_add_authenticator (ap->handle, ap->apreq,
					shishi_ticket_key(ap->ticket),
					ap->authenticatorkeyusage,
					ap->authenticator);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (ap->handle, "Could not set authenticator: %s\n",
			   shishi_strerror_details (ap->handle));
      return res;
    }

  return SHISHI_OK;
}

/**
 * shishi_ap_req_der:
 * @ap: structure that holds information about AP exchange
 * @out: output array with der encoding of AP-REQ.
 * @outlen: length of output array with der encoding of AP-REQ.
 *
 * Build AP-REQ using shishi_ap_req_buidl() and DER encode it.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_ap_req_der (Shishi_ap * ap, char *out, int *outlen)
{
  int rc;

  rc = shishi_ap_req_build(ap);
  if (rc != SHISHI_OK)
    return rc;

  rc = _shishi_a2d (ap->handle, ap->apreq, out, outlen);
  if (rc != SHISHI_OK)
    return rc;

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
shishi_ap_req_asn1 (Shishi_ap * ap, ASN1_TYPE * apreq)
{
  int rc;

  rc = shishi_ap_req_build(ap);
  if (rc != SHISHI_OK)
    return rc;

  *apreq = ap->apreq;

  return SHISHI_OK;
}

/**
 * shishi_ap_req_set:
 * @ap: structure that holds information about AP exchange
 * @apreq: apreq to store in AP.
 *
 * Set the AP-REQ in the AP exchange.
 **/
void
shishi_ap_req_set (Shishi_ap * ap, ASN1_TYPE apreq)
{
  if (ap->apreq)
    _shishi_asn1_done(ap->handle, ap->apreq);
  ap->apreq = apreq;
}

/**
 * shishi_ap_rep:
 * @ap: structure that holds information about AP exchange
 *
 * Return value: Returns the AP-REP from the AP exchange, or NULL if
 *               not yet set or an error occured.
 **/
ASN1_TYPE
shishi_ap_rep (Shishi_ap * ap)
{
  return ap->aprep;
}

/**
 * shishi_ap_rep_der_set:
 * @ap: structure that holds information about AP exchange
 * @der: input array with DER encoded AP-REP.
 * @derlen: length of input array with DER encoded AP-REP.
 *
 * DER decode AP-REP and set it AP exchange.  If decoding fails, the
 * AP-REP in the AP exchange is reset.
 *
 * Return value: Returns SHISHI_OK.
 **/
int
shishi_ap_rep_der_set (Shishi_ap * ap, char *der, int derlen)
{
  ap->aprep = shishi_d2a_aprep (ap->handle, der, derlen);

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
  int etype;
  int res;

  res = shishi_aprep_decrypt (ap->handle, ap->aprep,
			      shishi_ticket_key(ap->ticket),
			      SHISHI_KEYUSAGE_ENCAPREPPART, &ap->encapreppart);
  if (res != SHISHI_OK)
    return res;

  res = shishi_aprep_verify (ap->handle, ap->authenticator, ap->encapreppart);
  if (res != SHISHI_OK)
    return res;

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
shishi_ap_rep_verify_der (Shishi_ap * ap, char *der, int derlen)
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
shishi_ap_rep_verify_asn1 (Shishi_ap * ap, ASN1_TYPE aprep)
{
  int res;

  shishi_ap_rep_set (ap, aprep);

  res = shishi_ap_rep_verify (ap);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_ap_rep_set:
 * @ap: structure that holds information about AP exchange
 * @aprep: aprep to store in AP.
 *
 * Set the AP-REP in the AP exchange.
 **/
void
shishi_ap_rep_set (Shishi_ap * ap, ASN1_TYPE aprep)
{
  if (ap->aprep)
    _shishi_asn1_done(ap->handle, ap->aprep);
  ap->aprep = aprep;
}

/**
 * shishi_ap_rep:
 * @ap: structure that holds information about AP exchange
 *
 * Return value: Returns the EncAPREPPart from the AP exchange, or
 *               NULL if not yet set or an error occured.
 **/
ASN1_TYPE
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
shishi_ap_encapreppart_set (Shishi_ap * ap, ASN1_TYPE encapreppart)
{
  if (ap->encapreppart)
    _shishi_asn1_done(ap->handle, ap->encapreppart);
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
