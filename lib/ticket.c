/* ticket.c	ticket handling
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

int
shishi_ticket_realm_get (Shishi * handle,
			 ASN1_TYPE ticket, char *realm, int *realmlen)
{
  return _shishi_asn1_field (handle, ticket, realm, realmlen, "Ticket.realm");
}

int
shishi_ticket_sname_get (Shishi * handle,
			 ASN1_TYPE ticket, 
			 char *server, int *serverlen)
{
  return shishi_principal_name_get (handle, ticket, "Ticket.sname",
				    server, serverlen);
}

int
shishi_ticket_snamerealm_get (Shishi * handle,
			      ASN1_TYPE ticket, 
			      char *serverrealm, int *serverrealmlen)
{
  return shishi_principal_name_realm_get (handle, ticket, "Ticket.sname",
					  ticket, "Ticket.realm",
					  serverrealm, serverrealmlen);
}

/**
 * shishi_asn1ticket_get_enc_part_etype:
 * @handle: shishi handle as allocated by shishi_init().
 * @kdcrep: Ticket variable to get value from.
 * @etype: output variable that holds the value.
 * 
 * Extract Ticket.enc-part.etype.
 * 
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_asn1ticket_get_enc_part_etype (Shishi * handle,
				      ASN1_TYPE ticket, int *etype)
{
  int buflen;
  int res;

  *etype = 0;
  buflen = sizeof (*etype);
  res = _shishi_asn1_field (handle, ticket,
			    (char*)etype, &buflen, "Ticket.enc-part.etype");

  return res;
}

/**
 * shishi_ticket_principal:
 * @handle: shishi handle as allocated by shishi_init().
 * @ticket: input variable with ticket info.
 * 
 * Return value: Returns client principal of ticket.
 **/
char *
shishi_ticket_principal (Shishi * handle, Shishi_ticket * ticket)
{
  return ticket->principal ? ticket->principal : "<none>";
}

/**
 * shishi_ticket_ticket:
 * @handle: shishi handle as allocated by shishi_init().
 * @ticket: input variable with ticket info.
 * 
 * Return value: Returns actual ticket.
 **/
ASN1_TYPE
shishi_ticket_ticket (Shishi * handle, Shishi_ticket * ticket)
{
  return ticket->ticket;
}

/**
 * shishi_ticket_enckdcreppart:
 * @handle: shishi handle as allocated by shishi_init().
 * @ticket: input variable with ticket info.
 * 
 * Return value: Returns auxilliary ticket information.
 **/
ASN1_TYPE
shishi_ticket_enckdcreppart (Shishi * handle, 
				 Shishi_ticket * ticket)
{
  return ticket->enckdcreppart;
}

/**
 * shishi_ticket:
 * @handle: shishi handle as allocated by shishi_init().
 * @principal: input variable with client principal of ticket.
 * @ticket: input variable with ticket.
 * @enckdcreppart: input variable with auxilliary ticket information.
 * 
 * Create a new ticket handle.
 * 
 * Return value: Returns new ticket handle, or %NULL on error.
 **/
Shishi_ticket *
shishi_ticket (Shishi * handle, char *principal, 
		   ASN1_TYPE ticket, ASN1_TYPE enckdcreppart)
{
  Shishi_ticket *tkt;

  tkt = malloc(sizeof(*tkt));
  if (tkt == NULL)
    return NULL;

  tkt->principal = principal;
  tkt->ticket = ticket;
  tkt->enckdcreppart = enckdcreppart;

  return tkt;
}

int
shishi_ticket_flags (Shishi * handle,
			 Shishi_ticket * ticket, int *flags)
{
  int len = sizeof (*flags);
  int res;
  *flags = 0;
  res = _shishi_asn1_field (handle, ticket->enckdcreppart,
			    (char *) flags, &len, "EncKDCRepPart.flags");
  return res;
}

int
shishi_ticket_forwardable_p (Shishi * handle, Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (handle, ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_FORWARDABLE;
}

int
shishi_ticket_forwarded_p (Shishi * handle, Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (handle, ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_FORWARDED;
}

int
shishi_ticket_proxiable_p (Shishi * handle, Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (handle, ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_PROXIABLE;
}

int
shishi_ticket_proxy_p (Shishi * handle, Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (handle, ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_PROXY;
}

int
shishi_ticket_may_postdate_p (Shishi * handle, Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (handle, ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_MAY_POSTDATE;
}

int
shishi_ticket_postdated_p (Shishi * handle, Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (handle, ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_POSTDATED;
}

int
shishi_ticket_invalid_p (Shishi * handle, Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (handle, ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_INVALID;
}

int
shishi_ticket_renewable_p (Shishi * handle, Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (handle, ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_RENEWABLE;
}

int
shishi_ticket_initial_p (Shishi * handle, Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (handle, ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_INITIAL;
}

int
shishi_ticket_pre_authent_p (Shishi * handle, Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (handle, ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_PRE_AUTHENT;
}

int
shishi_ticket_hw_authent_p (Shishi * handle, Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (handle, ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_HW_AUTHENT;
}

int
shishi_ticket_transited_policy_checked_p (Shishi * handle,
					      Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (handle, ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_TRANSITED_POLICY_CHECKED;
}

int
shishi_ticket_ok_as_delegate_p (Shishi * handle,
				    Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (handle, ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_OK_AS_DELEGATE;
}

int
shishi_ticket_realm (Shishi * handle,
		     Shishi_ticket * ticket,
		     char *realm, int *realmlen)
{
  return shishi_ticket_realm_get (handle, ticket->ticket, realm, realmlen);
}

int
shishi_ticket_server (Shishi * handle,
		      Shishi_ticket * ticket,
		      char *service, int *servicelen)
{
  return shishi_ticket_sname_get (handle, ticket->ticket, 
				  service, servicelen);
}

int
shishi_ticket_server_realm (Shishi * handle,
			    Shishi_ticket * ticket,
			    char *servicerealm, int *servicerealmlen)
{
  return shishi_ticket_snamerealm_get (handle, ticket->ticket, 
				       servicerealm, servicerealmlen);
}

int
shishi_ticket_keytype (Shishi * handle,
			   Shishi_ticket * ticket, int *etype)
{
  int len = sizeof (*etype);
  *etype = 0;
  return _shishi_asn1_field (handle, ticket->enckdcreppart,
			     (char *) etype, &len,
			     "EncKDCRepPart.key.keytype");
}

int
shishi_ticket_authtime (Shishi * handle,
			    Shishi_ticket * ticket,
			    char *authtime, int *authtimelen)
{
  return _shishi_asn1_field (handle, ticket->enckdcreppart,
			     authtime, authtimelen, "EncKDCRepPart.authtime");
}

time_t
shishi_ticket_authctime (Shishi * handle, Shishi_ticket * ticket)
{
  char authtime[GENERALIZEDTIME_TIME_LEN + 1];
  int authtimelen;
  time_t t;
  int res;

  authtimelen = sizeof (authtime);
  res = shishi_ticket_authtime (handle, ticket, authtime, &authtimelen);
  if (res != SHISHI_OK)
    return (time_t) - 1;

  authtime[GENERALIZEDTIME_TIME_LEN] = '\0';

  t = shishi_generalize_ctime (handle, authtime);

  return t;
}

int
shishi_ticket_starttime (Shishi * handle,
			     Shishi_ticket * ticket,
			     char *starttime, int *starttimelen)
{
  return _shishi_asn1_optional_field (handle, ticket->enckdcreppart,
				      starttime, starttimelen,
				      "EncKDCRepPart.starttime");
}

time_t
shishi_ticket_startctime (Shishi * handle, Shishi_ticket * ticket)
{
  char starttime[GENERALIZEDTIME_TIME_LEN + 1];
  int starttimelen;
  time_t t;
  int res;

  starttimelen = sizeof (starttime);
  res =
    shishi_ticket_starttime (handle, ticket, starttime, &starttimelen);
  if (res != SHISHI_OK || starttimelen == 0)
    return (time_t) - 1;

  starttime[GENERALIZEDTIME_TIME_LEN] = '\0';

  t = shishi_generalize_ctime (handle, starttime);

  return t;
}

int
shishi_ticket_endtime (Shishi * handle,
			   Shishi_ticket * ticket,
			   char *endtime, int *endtimelen)
{
  return _shishi_asn1_field (handle, ticket->enckdcreppart,
			     endtime, endtimelen, "EncKDCRepPart.endtime");
}

time_t
shishi_ticket_endctime (Shishi * handle, Shishi_ticket * ticket)
{
  char endtime[GENERALIZEDTIME_TIME_LEN + 1];
  int endtimelen;
  time_t t;
  int res;

  endtimelen = sizeof (endtime);
  res = shishi_ticket_endtime (handle, ticket, endtime, &endtimelen);
  if (res != SHISHI_OK)
    return (time_t) - 1;

  endtime[GENERALIZEDTIME_TIME_LEN] = '\0';

  t = shishi_generalize_ctime (handle, endtime);

  return t;
}

int
shishi_ticket_renew_till (Shishi * handle,
			      Shishi_ticket * ticket,
			      char *renewtill, int *renewtilllen)
{
  return _shishi_asn1_optional_field (handle, ticket->enckdcreppart,
				      renewtill, renewtilllen,
				      "EncKDCRepPart.renew-till");
}

time_t
shishi_ticket_renew_tillc (Shishi * handle, Shishi_ticket * ticket)
{
  char renewtill[GENERALIZEDTIME_TIME_LEN + 1];
  int renewtilllen;
  time_t t;
  int res;

  renewtilllen = sizeof (renewtill);
  res =
    shishi_ticket_renew_till (handle, ticket, renewtill, &renewtilllen);
  if (res != SHISHI_OK || renewtilllen == 0)
    return (time_t) - 1;

  renewtill[GENERALIZEDTIME_TIME_LEN] = '\0';

  t = shishi_generalize_ctime (handle, renewtill);

  return t;
}

int
shishi_ticket_valid_at_time_p (Shishi * handle,
				   Shishi_ticket * ticket, time_t now)
{
  time_t starttime, endtime;

  starttime = shishi_ticket_startctime (handle, ticket);
  if (starttime == (time_t) - 1)
    starttime = shishi_ticket_authctime (handle, ticket);
  endtime = shishi_ticket_endctime (handle, ticket);

  return starttime <= now && now <= endtime;
}

int
shishi_ticket_valid_now_p (Shishi * handle, Shishi_ticket * ticket)
{
  return shishi_ticket_valid_at_time_p (handle, ticket, time (NULL));
}

int
shishi_ticket_print (Shishi * handle,
		     Shishi_ticket * ticket, FILE * fh)
{
  char buf[BUFSIZ];
  char *p;
  int buflen;
  int etype, flags;
  int res;
  time_t t;

  printf ("%s:\n", shishi_ticket_principal (handle, ticket));

  t = shishi_ticket_authctime (handle, ticket);
  printf (_("Authtime:\t%s"), ctime (&t));

  t = shishi_ticket_startctime (handle, ticket);
  if (t != (time_t) - 1)
    printf (_("Starttime:\t%s"), ctime (&t));

  t = shishi_ticket_endctime (handle, ticket);
  p = ctime (&t);
  p[strlen (p) - 1] = '\0';
  printf (_("Endtime:\t%s\t%s\n"), p,
	  shishi_ticket_valid_now_p (handle,
					 ticket) ? "valid" : "EXPIRED");

  t = shishi_ticket_renew_tillc (handle, ticket);
  if (t != (time_t) - 1)
    printf (_("Renewable until:\t%s"), ctime (&t));

  buflen = sizeof (buf);
  buf[0] = '\0';
  res = shishi_ticket_server (handle, ticket, buf, &buflen);
  if (res != SHISHI_OK)
    return res;
  buf[buflen] = '\0';
  printf (_("Service:\t%s\n"), buf);

  res = shishi_ticket_keytype (handle, ticket, &etype);
  if (res != SHISHI_OK)
    return res;
  printf (_("Key type:\t%s (%d)\n"), shishi_cipher_name (etype), etype);

  res = shishi_ticket_flags (handle, ticket, &flags);
  if (res != SHISHI_OK)
    return res;
  printf (_
	  ("Flags:\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n"),
	  flags, shishi_ticket_forwardable_p (handle,
						  ticket) ? "FORWARDABLE" :
	  "", shishi_ticket_forwarded_p (handle,
					     ticket) ? "FORWARDED" : "",
	  shishi_ticket_proxiable_p (handle, ticket) ? "PROXIABLE" : "",
	  shishi_ticket_proxy_p (handle, ticket) ? "PROXY" : "",
	  shishi_ticket_may_postdate_p (handle,
					    ticket) ? "MAYPOSTDATE" : "",
	  shishi_ticket_postdated_p (handle, ticket) ? "POSTDATED" : "",
	  shishi_ticket_invalid_p (handle, ticket) ? "INVALID" : "",
	  shishi_ticket_renewable_p (handle, ticket) ? "RENEWABLE" : "",
	  shishi_ticket_initial_p (handle, ticket) ? "INITIAL" : "",
	  shishi_ticket_pre_authent_p (handle,
					   ticket) ? "PREAUTHENT" : "",
	  shishi_ticket_hw_authent_p (handle, ticket) ? "HWAUTHENT" : "",
	  shishi_ticket_transited_policy_checked_p (handle,
							ticket) ?
	  "TRANSITEDPOLICYCHECKED" : "",
	  shishi_ticket_ok_as_delegate_p (handle,
					      ticket) ? "OKASDELEGATE" : "");



  return SHISHI_OK;
}

int
shishi_ticket_authenticator_data (Shishi * handle,
				      Shishi_ticket * ticket,
				      char *data,
				      int datalen, ASN1_TYPE * authenticator)
{
  int res;

  *authenticator = shishi_authenticator (handle);
  if (*authenticator == NULL)
    {
      shishi_error_printf (handle, "Could not create Authenticator: %s\n",
			   shishi_strerror_details (handle));
      return SHISHI_ASN1_ERROR;
    }

  res = shishi_authenticator_add_cksum (handle, *authenticator,
					ticket->enckdcreppart,
					data, datalen);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle,
			   "Could not add checksum to authenticator: %s\n",
			   shishi_strerror_details (handle));
      return res;
    }

  return SHISHI_OK;
}

int
shishi_ticket_authenticator (Shishi * handle,
				 Shishi_ticket * ticket,
				 ASN1_TYPE node,
				 char *field, ASN1_TYPE * authenticator)
{
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  unsigned char der[BUFSIZ];
  size_t derlen;
  int res;

  if (node != ASN1_TYPE_EMPTY)
    {
      res = asn1_der_coding (node, field, der, &derlen, errorDescription);
      if (res != ASN1_SUCCESS)
	{
	  shishi_error_printf (handle, "Could not DER encode node: %s\n",
			       errorDescription);
	  return SHISHI_ASN1_ERROR;
	}

      memmove (der, der + 2, derlen - 2);
      derlen -= 2;
    }
  else
    derlen = 0;

  res = shishi_ticket_authenticator_data (handle,
					      ticket,
					      der, derlen, authenticator);
  return res;
}

int
shishi_ticket_apreq_data (Shishi * handle,
			  Shishi_ticket * ticket,
			  char *data, int datalen, ASN1_TYPE * apreq)
{
  ASN1_TYPE authenticator = ASN1_TYPE_EMPTY;
  int res;

  *apreq = shishi_apreq (handle);
  if (apreq == NULL)
    {
      shishi_error_printf (handle, "Could not create APREQ: %s\n",
			   shishi_strerror_details (handle));
      return SHISHI_ASN1_ERROR;
    }

  res = shishi_apreq_set_ticket (handle, *apreq, ticket->ticket);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not set ticket: %s\n",
			   shishi_strerror_details (handle));
      return res;
    }

  res = shishi_ticket_authenticator_data (handle,
					      ticket,
					      data, datalen, &authenticator);
  if (res != SHISHI_OK)
    {
      printf (_("Could not make authenticator: %s\n"),
	      shishi_strerror_details (handle));
      return res;
    }

  res = shishi_apreq_add_authenticator (handle, *apreq,
					ticket->enckdcreppart,
					authenticator);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, "Could not set authenticator: %s\n",
			   shishi_strerror_details (handle));
      return res;
    }

  return SHISHI_OK;
}

int
shishi_ticket_apreq (Shishi * handle,
		     Shishi_ticket * ticket,
		     ASN1_TYPE node, char *field, ASN1_TYPE * apreq)
{
  char errorDescription[MAX_ERROR_DESCRIPTION_SIZE];
  unsigned char der[BUFSIZ];
  size_t derlen;
  int res;

  if (node != ASN1_TYPE_EMPTY)
    {
      res = asn1_der_coding (node, field, der, &derlen, errorDescription);
      if (res != ASN1_SUCCESS)
	{
	  shishi_error_printf (handle, "Could not DER encode node: %s\n",
			       errorDescription);
	  return SHISHI_ASN1_ERROR;
	}

      memmove (der, der + 2, derlen - 2);
      derlen -= 2;
    }
  else
    derlen = 0;

  res = shishi_ticket_apreq_data (handle, ticket, der, derlen, apreq);

  return res;
}

int
shishi_ticket_decrypt (Shishi * handle,
		       ASN1_TYPE ticket,
		       int keytype,
		       char *key, 
		       int keylen, 
		       ASN1_TYPE * encticketpart)
{
  int res;
  int i, len;
  int buflen = BUFSIZ;
  unsigned char buf[BUFSIZ];
  unsigned char cipher[BUFSIZ];
  int realmlen = BUFSIZ;
  int cipherlen;
  int etype;

  res = shishi_asn1ticket_get_enc_part_etype (handle, ticket, &etype);
  if (res != SHISHI_OK)
    return res;

  if (etype != keytype)
    return SHISHI_KDCREP_BAD_KEYTYPE;

  cipherlen = BUFSIZ;
  res = _shishi_asn1_field (handle, ticket, cipher, &cipherlen,
			    "Ticket.enc-part.cipher");
  if (res != SHISHI_OK)
    return res;

  res = shishi_decrypt (handle, etype, buf, &buflen, cipher, cipherlen,
			key, keylen);

  if (res != SHISHI_OK)
    {
      if (!SILENT(handle))
	printf ("des_decrypt failed: %s\n", shishi_strerror_details (handle));
      shishi_error_printf (handle,
			   "des_decrypt fail, most likely wrong password\n");
      return res;
    }

  /* The crypto in kerberos is so 1980; no length indicator. Trim off pad
     bytes until we can parse it. */
  for (i = 0; i < 8; i++)
    {
      if (DEBUG (handle))
	printf ("Trying with %d pad in enckdcrep...\n", i);

      *encticketpart = shishi_d2a_encticketpart (handle, &buf[0], buflen - i);
      if (*encticketpart != ASN1_TYPE_EMPTY)
	break;
    }

  if (*encticketpart == ASN1_TYPE_EMPTY)
    {
      shishi_error_printf (handle, "Could not DER decode EncTicketPart. "
			   "Password probably correct (decrypt ok) though\n");
      return SHISHI_ASN1_ERROR;
    }

  return SHISHI_OK;
}
