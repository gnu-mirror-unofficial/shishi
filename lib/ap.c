/* ap.c	AP functions
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

#define APOPTION_RESERVED "reserved"
#define APOPTION_USE_SESSION_KEY "use-session-key"
#define APOPTION_MUTUAL_REQUIRED "mutual-required"
#define APOPTION_UNKNOWN "unknown"

char *
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
shishi_ap_string2option (char *str)
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



int
shishi_ap (Shishi * handle, Shishi_ticket * ticket, Shishi_ap ** ap)
{
  /* XXX rename this function */
  return shishi_ap_data (handle, ticket, NULL, 0, ap);
}

int
shishi_ap_data (Shishi * handle,
		Shishi_ticket * ticket,
		char *data, int datalen, Shishi_ap ** ap)
{
  Shishi_ap *lap;
  int res;
  /* XXX rename this function */

  *ap = malloc (sizeof (**ap));
  if (*ap == NULL)
    return SHISHI_MALLOC_ERROR;
  lap = *ap;

  lap->ticket = ticket;

  /* XXX this assume a client -- move this to shishi_ap_request */

  res = shishi_ticket_apreq_data (handle, ticket, data, datalen, &lap->apreq);
  if (res != SHISHI_OK)
    {
      return res;
    }

  lap->authenticator = shishi_last_authenticator (handle);

  return SHISHI_OK;
}

/**
 * shishi_ap_get_ticket:
 * @ap: structure that holds information about AP exchange
 * 
 * Return value: Returns the ticket from the AP exchange, or NULL if
 *               not yet set or an error occured.
 **/
Shishi_ticket *
shishi_ap_get_ticket (Shishi_ap * ap)
{
  return ap->ticket;
}

/**
 * shishi_ap_get_authenticator:
 * @ap: structure that holds information about AP exchange
 * 
 * Return value: Returns the Authenticator from the AP exchange, or
 *               NULL if not yet set or an error occured.
 **/
ASN1_TYPE
shishi_ap_get_authenticator (Shishi_ap * ap)
{
  return ap->authenticator;
}

/**
 * shishi_ap_get_apreq:
 * @ap: structure that holds information about AP exchange
 * 
 * Return value: Returns the AP-REQ from the AP exchange, or NULL if
 *               not yet set or an error occured.
 **/
ASN1_TYPE
shishi_ap_get_apreq (Shishi_ap * ap)
{
  return ap->apreq;
}

/**
 * shishi_ap_get_aprep:
 * @ap: structure that holds information about AP exchange
 * 
 * Return value: Returns the AP-REP from the AP exchange, or NULL if
 *               not yet set or an error occured.
 **/
ASN1_TYPE
shishi_ap_get_aprep (Shishi_ap * ap)
{
  return ap->aprep;
}

/**
 * shishi_ap_get_aprep:
 * @ap: structure that holds information about AP exchange
 * 
 * Return value: Returns the EncAPREPPart from the AP exchange, or
 *               NULL if not yet set or an error occured.
 **/
ASN1_TYPE
shishi_ap_get_encapreppart (Shishi_ap * ap)
{
  return ap->encapreppart;
}

int
shishi_ap_request_get_der (Shishi * handle,
			   Shishi_ap * ap, char *out, int *outlen)
{
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  int rc;

  /* XXX rebuild authenticator in AP-REQ too */

  rc = asn1_der_coding (ap->apreq, ap->apreq->name, out, outlen,
			errorDescription);
  if (rc != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  return SHISHI_OK;
}


int
shishi_ap_reply_set_der (Shishi * handle,
			 Shishi_ap * ap, char *der, int derlen)
{
  ap->aprep = shishi_d2a_aprep (handle, der, derlen);

  return SHISHI_OK;
}

int
shishi_ap_reply_verify_der (Shishi * handle,
			    Shishi_ap * ap, char *der, int derlen)
{
  ASN1_TYPE aprep;
  unsigned char key[MAX_KEY_LEN];
  int keylen;
  int etype, keytype;
  int res;

  aprep = shishi_d2a_aprep (handle, der, derlen);
  if (aprep == ASN1_TYPE_EMPTY)
    return SHISHI_ASN1_ERROR;

  res = shishi_ap_reply_verify (handle, ap, aprep);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

int
shishi_ap_reply_verify (Shishi * handle, Shishi_ap * ap, ASN1_TYPE aprep)
{
  Shishi_key *key;
  int etype;
  int res;

  res = shishi_enckdcreppart_get_key (handle,
				      shishi_ticket_enckdcreppart (ap->ticket),
				      &key);
  if (res != SHISHI_OK)
    return res;

  res = shishi_aprep_decrypt (handle, aprep, key, SHISHI_KEYUSAGE_ENCAPREPPART,
			      &ap->encapreppart);
  if (res != SHISHI_OK)
    return res;

  shishi_key_done(key);

  res = shishi_aprep_verify (handle, ap->authenticator, ap->encapreppart);
  if (res != SHISHI_OK)
    return res;

  ap->aprep = aprep;

  return SHISHI_OK;
}
