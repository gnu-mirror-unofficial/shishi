/* ticket.c	ticket handling
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

struct Shishi_ticket
{
  Shishi *handle;
  ASN1_TYPE ticket;
  ASN1_TYPE kdcrep;
  ASN1_TYPE enckdcreppart;
  ASN1_TYPE encticketpart;
  Shishi_key *key;
};

int
shishi_ticket_realm_get (Shishi * handle,
			 ASN1_TYPE ticket, char *realm, int *realmlen)
{
  return _shishi_asn1_field (handle, ticket, realm, realmlen, "Ticket.realm");
}

int
shishi_ticket_sname_get (Shishi * handle,
			 ASN1_TYPE ticket, char *server, int *serverlen)
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
			    (char *) etype, &buflen, "Ticket.enc-part.etype");

  return res;
}

/**
 * shishi_ticket_cnamerealm:
 * @ticket: input variable with ticket info.
 * XXX
 *
 * Return value: Returns client principal and realm of ticket.
 **/
int
shishi_ticket_cnamerealm (Shishi_ticket * ticket,
			  char *cnamerealm, int *cnamerealmlen)
{
  return shishi_principal_name_realm_get (ticket->handle,
					  ticket->kdcrep, "KDC-REP.cname",
					  ticket->kdcrep, "KDC-REP.crealm",
					  cnamerealm, cnamerealmlen);
}

/**
 * shishi_ticket_ticket:
 * @ticket: input variable with ticket info.
 *
 * Return value: Returns actual ticket.
 **/
ASN1_TYPE
shishi_ticket_ticket (Shishi_ticket * ticket)
{
  return ticket->ticket;
}

/**
 * shishi_ticket_enckdcreppart:
 * @ticket: input variable with ticket info.
 *
 * Return value: Returns auxilliary ticket information.
 **/
ASN1_TYPE
shishi_ticket_enckdcreppart (Shishi_ticket * ticket)
{
  return ticket->enckdcreppart;
}

/**
 * shishi_ticket_kdcrep:
 * @ticket: input variable with ticket info.
 *
 * Return value: Returns KDC-REP information.
 **/
ASN1_TYPE
shishi_ticket_kdcrep (Shishi_ticket * ticket)
{
  return ticket->kdcrep;
}

/**
 * shishi_ticket_encticketpart:
 * @ticket: input variable with ticket info.
 *
 * Return value: Returns EncTicketPart information.
 **/
ASN1_TYPE
shishi_ticket_encticketpart (Shishi_ticket * ticket)
{
  return ticket->encticketpart;
}

/**
 * shishi_ticket_key:
 * @ticket: input variable with ticket info.
 *
 * Return value: Returns key extracted from enckdcreppart.
 **/
Shishi_key *
shishi_ticket_key (Shishi_ticket * ticket)
{
  if (!ticket->key)
    {
      int res;

      res = shishi_enckdcreppart_get_key (ticket->handle,
					  shishi_ticket_enckdcreppart (ticket),
					  &ticket->key);
      if (res != SHISHI_OK)
	return NULL;
    }

  return ticket->key;
}

/**
 * shishi_ticket:
 * @handle: shishi handle as allocated by shishi_init().
 * @ticket: input variable with ticket.
 * @enckdcreppart: input variable with auxilliary ticket information.
 * @kdcrep: input variable with KDC-REP ticket information.
 *
 * Create a new ticket handle.
 *
 * Return value: Returns new ticket handle, or %NULL on error.
 **/
Shishi_ticket *
shishi_ticket (Shishi * handle,
	       ASN1_TYPE ticket, ASN1_TYPE enckdcreppart, ASN1_TYPE kdcrep)
{
  Shishi_ticket *tkt;

  tkt = malloc (sizeof (*tkt));
  if (tkt == NULL)
    return NULL;

  memset(tkt, 0, sizeof(*tkt));

  tkt->handle = handle;
  tkt->ticket = ticket;
  tkt->enckdcreppart = enckdcreppart;
  tkt->kdcrep = kdcrep;

  return tkt;
}

int
shishi_ticket_flags (Shishi_ticket * ticket, int *flags)
{
  unsigned char buf[4];
  int buflen;
  int i;
  int res;

  memset (buf, 0, sizeof (buf));
  buflen = sizeof (buf);
  res = _shishi_asn1_field (ticket->handle, ticket->enckdcreppart,
			    buf, &buflen, "EncKDCRepPart.flags");
  if (res != SHISHI_OK)
    {
      shishi_error_set (ticket->handle, libtasn1_strerror (res));
      return SHISHI_ASN1_ERROR;
    }

  *flags = 0;
  for (i = 0; i < 4; i++)
    {
      *flags |= (((buf[i] >> 7) & 0x01) |
		 ((buf[i] >> 5) & 0x02) |
		 ((buf[i] >> 3) & 0x04) |
		 ((buf[i] >> 1) & 0x08) |
		 ((buf[i] << 1) & 0x10) |
		 ((buf[i] << 3) & 0x20) |
		 ((buf[i] << 5) & 0x40) |
		 ((buf[i] << 7) & 0x80)) << (8*i);
    }

  return SHISHI_OK;
}

int
shishi_ticket_forwardable_p (Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_FORWARDABLE;
}

int
shishi_ticket_forwarded_p (Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_FORWARDED;
}

int
shishi_ticket_proxiable_p (Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_PROXIABLE;
}

int
shishi_ticket_proxy_p (Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_PROXY;
}

int
shishi_ticket_may_postdate_p (Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_MAY_POSTDATE;
}

int
shishi_ticket_postdated_p (Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_POSTDATED;
}

int
shishi_ticket_invalid_p (Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_INVALID;
}

int
shishi_ticket_renewable_p (Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_RENEWABLE;
}

int
shishi_ticket_initial_p (Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_INITIAL;
}

int
shishi_ticket_pre_authent_p (Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_PRE_AUTHENT;
}

int
shishi_ticket_hw_authent_p (Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_HW_AUTHENT;
}

int
shishi_ticket_transited_policy_checked_p (Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_TRANSITED_POLICY_CHECKED;
}

int
shishi_ticket_ok_as_delegate_p (Shishi_ticket * ticket)
{
  int flags = 0;

  shishi_ticket_flags (ticket, &flags);

  return flags & SHISHI_TICKETFLAGS_OK_AS_DELEGATE;
}

int
shishi_ticket_realm (Shishi_ticket * ticket, char *realm, int *realmlen)
{
  return shishi_ticket_realm_get (ticket->handle, ticket->ticket,
				  realm, realmlen);
}

int
shishi_ticket_server (Shishi_ticket * ticket,
		      const char *server, int *serverlen)
{
  return shishi_ticket_sname_get (ticket->handle, ticket->ticket,
				  server, serverlen);
}

int
shishi_ticket_server_p (Shishi_ticket * ticket, const char *server)
{
  char *buf;
  int buflen;
  int res;

  buflen = strlen (server) + 1;
  buf = malloc (buflen);
  if (buf == NULL)
    return 0;

  res = shishi_ticket_server (ticket, buf, &buflen);
  if (res != SHISHI_OK)
    {
      free (buf);
      return 0;
    }
  buf[buflen] = '\0';

  if (strcmp (server, buf) != 0)
    {
      free (buf);
      return 0;
    }

  free (buf);

  return 1;
}

int
shishi_ticket_server_realm (Shishi_ticket * ticket,
			    char *serverrealm, int *serverrealmlen)
{
  return shishi_ticket_snamerealm_get (ticket->handle, ticket->ticket,
				       serverrealm, serverrealmlen);
}

int
shishi_ticket_keytype (Shishi_ticket * ticket, int *etype)
{
  return _shishi_asn1_integer_field (ticket->handle,
				     ticket->enckdcreppart, etype,
				     "EncKDCRepPart.key.keytype");
}

int
shishi_ticket_keytype_p (Shishi_ticket * ticket, int etype)
{
  int tktetype;
  int rc;

  rc = _shishi_asn1_integer_field (ticket->handle,
				   ticket->enckdcreppart, &tktetype,
				   "EncKDCRepPart.key.keytype");
  if (rc != SHISHI_OK)
    return 0;

  return etype == tktetype;
}

int
shishi_ticket_lastreq (Shishi_ticket * ticket,
		       char *lrtime,
		       int *lrtimelen,
		       Shihi_lrtype lrtype)
{
  unsigned char format[BUFSIZ];
  int tmplrtype;
  int res;
  int i, n;

  res = asn1_number_of_elements (ticket->enckdcreppart,
				 "EncKDCRepPart.last-req", &n);
  if (res != ASN1_SUCCESS)
    return SHISHI_ASN1_ERROR;

  for (i = 1; i <= n; i++)
    {
      sprintf (format, "EncKDCRepPart.last-req.?%d.lr-type", i);

      res = _shishi_asn1_integer_field (ticket->handle, ticket->enckdcreppart,
					&tmplrtype, format);
      if (res != SHISHI_OK)
	return SHISHI_ASN1_ERROR;

      if (lrtype == tmplrtype)
	{
	  sprintf (format, "EncKDCRepPart.last-req.?%d.lr-value", i);

	  res = _shishi_asn1_field (ticket->handle, ticket->enckdcreppart,
				    lrtime, lrtimelen, format);
	  if (res != SHISHI_OK)
	    return SHISHI_ASN1_ERROR;

	  return SHISHI_OK;
	}
    }

  return !SHISHI_OK;
}

time_t
shishi_ticket_lastreqc (Shishi_ticket * ticket, Shihi_lrtype lrtype)
{
  char lrtime[GENERALIZEDTIME_TIME_LEN + 1];
  int lrtimelen;
  time_t t;
  int res;

  lrtimelen = sizeof (lrtime);
  res = shishi_ticket_lastreq (ticket, lrtime, &lrtimelen, lrtype);
  if (res != SHISHI_OK)
    return (time_t) - 1;

  lrtime[GENERALIZEDTIME_TIME_LEN] = '\0';

  t = shishi_generalize_ctime (ticket->handle, lrtime);

  return t;
}

int
shishi_ticket_lastreq_pretty_print (Shishi_ticket * ticket, FILE *fh)
{
  time_t t;
  int res;

  t = shishi_ticket_lastreqc (ticket, SHISHI_LRTYPE_LAST_INITIAL_TGT_REQUEST);
  if (t != (time_t) - 1)
    printf(_("Time of last initial request for a TGT:\t%s"), ctime(&t));

  t = shishi_ticket_lastreqc (ticket, SHISHI_LRTYPE_LAST_INITIAL_REQUEST);
  if (t != (time_t) - 1)
    printf("Time of last initial request:\t%s", ctime(&t));

  t = shishi_ticket_lastreqc (ticket, SHISHI_LRTYPE_NEWEST_TGT_ISSUE);
  if (t != (time_t) - 1)
    printf("Time of issue for the newest ticket-granting ticket used:\t%s",
	   ctime(&t));

  t = shishi_ticket_lastreqc (ticket, SHISHI_LRTYPE_LAST_RENEWAL);
  if (t != (time_t) - 1)
    printf("Time of the last renewal:\t%s", ctime(&t));

  t = shishi_ticket_lastreqc (ticket, SHISHI_LRTYPE_LAST_REQUEST);
  if (t != (time_t) - 1)
    printf("Time of last request:\t%s", ctime(&t));

  return SHISHI_OK;
}

int
shishi_ticket_authtime (Shishi_ticket * ticket,
			char *authtime, int *authtimelen)
{
  return _shishi_asn1_field (ticket->handle, ticket->enckdcreppart,
			     authtime, authtimelen, "EncKDCRepPart.authtime");
}

time_t
shishi_ticket_authctime (Shishi_ticket * ticket)
{
  char authtime[GENERALIZEDTIME_TIME_LEN + 1];
  int authtimelen;
  time_t t;
  int res;

  authtimelen = sizeof (authtime);
  res = shishi_ticket_authtime (ticket, authtime, &authtimelen);
  if (res != SHISHI_OK)
    return (time_t) - 1;

  authtime[GENERALIZEDTIME_TIME_LEN] = '\0';

  t = shishi_generalize_ctime (ticket->handle, authtime);

  return t;
}

int
shishi_ticket_starttime (Shishi_ticket * ticket,
			 char *starttime, int *starttimelen)
{
  return _shishi_asn1_optional_field (ticket->handle, ticket->enckdcreppart,
				      starttime, starttimelen,
				      "EncKDCRepPart.starttime");
}

time_t
shishi_ticket_startctime (Shishi_ticket * ticket)
{
  char starttime[GENERALIZEDTIME_TIME_LEN + 1];
  int starttimelen;
  time_t t;
  int res;

  starttimelen = sizeof (starttime);
  res = shishi_ticket_starttime (ticket, starttime, &starttimelen);
  if (res != SHISHI_OK || starttimelen == 0)
    return (time_t) - 1;

  starttime[GENERALIZEDTIME_TIME_LEN] = '\0';

  t = shishi_generalize_ctime (ticket->handle, starttime);

  return t;
}

int
shishi_ticket_endtime (Shishi_ticket * ticket, char *endtime, int *endtimelen)
{
  return _shishi_asn1_field (ticket->handle, ticket->enckdcreppart,
			     endtime, endtimelen, "EncKDCRepPart.endtime");
}

time_t
shishi_ticket_endctime (Shishi_ticket * ticket)
{
  char endtime[GENERALIZEDTIME_TIME_LEN + 1];
  int endtimelen;
  time_t t;
  int res;

  endtimelen = sizeof (endtime);
  res = shishi_ticket_endtime (ticket, endtime, &endtimelen);
  if (res != SHISHI_OK)
    return (time_t) - 1;

  endtime[GENERALIZEDTIME_TIME_LEN] = '\0';

  t = shishi_generalize_ctime (ticket->handle, endtime);

  return t;
}

int
shishi_ticket_renew_till (Shishi_ticket * ticket,
			  char *renewtill, int *renewtilllen)
{
  return _shishi_asn1_optional_field (ticket->handle, ticket->enckdcreppart,
				      renewtill, renewtilllen,
				      "EncKDCRepPart.renew-till");
}

time_t
shishi_ticket_renew_tillc (Shishi_ticket * ticket)
{
  char renewtill[GENERALIZEDTIME_TIME_LEN + 1];
  int renewtilllen;
  time_t t;
  int res;

  renewtilllen = sizeof (renewtill);
  res = shishi_ticket_renew_till (ticket, renewtill, &renewtilllen);
  if (res != SHISHI_OK || renewtilllen == 0)
    return (time_t) - 1;

  renewtill[GENERALIZEDTIME_TIME_LEN] = '\0';

  t = shishi_generalize_ctime (ticket->handle, renewtill);

  return t;
}

int
shishi_ticket_valid_at_time_p (Shishi_ticket * ticket, time_t now)
{
  time_t starttime, endtime;

  starttime = shishi_ticket_startctime (ticket);
  if (starttime == (time_t) - 1)
    starttime = shishi_ticket_authctime (ticket);
  endtime = shishi_ticket_endctime (ticket);

  return starttime <= now && now <= endtime;
}

int
shishi_ticket_valid_now_p (Shishi_ticket * ticket)
{
  return shishi_ticket_valid_at_time_p (ticket, time (NULL));
}

int
shishi_ticket_pretty_print (Shishi_ticket * ticket, FILE * fh)
{
  char buf[BUFSIZ];
  char *p;
  int buflen;
  int keytype, etype, flags;
  int res;
  time_t t;

  buflen = sizeof (buf);
  buf[0] = '\0';
  res = shishi_ticket_cnamerealm (ticket, buf, &buflen);
  if (res != SHISHI_OK)
    return res;
  buf[buflen] = '\0';
  printf ("%s:\n", buf);

  t = shishi_ticket_authctime (ticket);
  printf (_("Authtime:\t%s"), ctime (&t));

  t = shishi_ticket_startctime (ticket);
  if (t != (time_t) - 1)
    printf (_("Starttime:\t%s"), ctime (&t));

  t = shishi_ticket_endctime (ticket);
  p = ctime (&t);
  p[strlen (p) - 1] = '\0';
  printf (_("Endtime:\t%s"), p);
  if (!shishi_ticket_valid_now_p (ticket))
    printf (" (EXPIRED)");
  printf ("\n");

  t = shishi_ticket_renew_tillc (ticket);
  if (t != (time_t) - 1)
    printf (_("Renewable until:\t%s"), ctime (&t));

  buflen = sizeof (buf);
  buf[0] = '\0';
  res = shishi_ticket_server (ticket, buf, &buflen);
  if (res != SHISHI_OK)
    return res;
  buf[buflen] = '\0';
  res = shishi_asn1ticket_get_enc_part_etype (ticket->handle,
					      ticket->ticket, &keytype);
  if (res != SHISHI_OK)
    return res;
  printf (_("Server:\t\t%s key %s (%d)\n"), buf,
	  shishi_cipher_name (keytype), keytype);

  res = shishi_ticket_keytype (ticket, &keytype);
  if (res != SHISHI_OK)
    return res;
  res = shishi_kdcrep_get_enc_part_etype (ticket->handle,
					  ticket->kdcrep, &etype);
  if (res != SHISHI_OK)
    return res;
  printf (_("Ticket key:\t%s (%d) protected by %s (%d)\n"),
	  shishi_cipher_name (keytype), keytype,
	  shishi_cipher_name (etype), etype);


  res = shishi_ticket_flags (ticket, &flags);
  if (res != SHISHI_OK)
    return res;
  if (flags)
    {
      printf (_("Ticket flags:\t"));
      if (shishi_ticket_forwardable_p (ticket))
	printf ("FORWARDABLE ");
      if (shishi_ticket_forwarded_p (ticket))
	printf ("FORWARDED ");
      if (shishi_ticket_proxiable_p (ticket))
	printf ("PROXIABLE ");
      if (shishi_ticket_proxy_p (ticket))
	printf ("PROXY ");
      if (shishi_ticket_may_postdate_p (ticket))
	printf ("MAYPOSTDATE ");
      if (shishi_ticket_postdated_p (ticket))
	printf ("POSTDATED ");
      if (shishi_ticket_invalid_p (ticket))
	printf ("INVALID ");
      if (shishi_ticket_renewable_p (ticket))
	printf ("RENEWABLE ");
      if (shishi_ticket_initial_p (ticket))
	printf ("INITIAL ");
      if (shishi_ticket_pre_authent_p (ticket))
	printf ("PREAUTHENT ");
      if (shishi_ticket_hw_authent_p (ticket))
	printf ("HWAUTHENT ");
      if (shishi_ticket_transited_policy_checked_p (ticket))
	printf ("TRANSITEDPOLICYCHECKED ");
      if (shishi_ticket_ok_as_delegate_p (ticket))
	printf ("OKASDELEGATE ");
      printf ("(%d)\n", flags);
    }

  return SHISHI_OK;
}

int
shishi_ticket_decrypt (Shishi_ticket * ticket,
		       Shishi_key *key)
{
  int rc;
  ASN1_TYPE encticketpart;

  rc = shishi_asn1ticket_decrypt(ticket->handle, ticket->ticket, key,
				 &encticketpart);
  if (rc != SHISHI_OK)
    return rc;

  ticket->encticketpart = encticketpart;

  return SHISHI_OK;
}

int
shishi_asn1ticket_decrypt (Shishi * handle,
			   ASN1_TYPE ticket,
			   Shishi_key *key,
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

  if (etype != shishi_key_type(key))
    return SHISHI_TICKET_BAD_KEYTYPE;

  cipherlen = BUFSIZ;
  res = _shishi_asn1_field (handle, ticket, cipher, &cipherlen,
			    "Ticket.enc-part.cipher");
  if (res != SHISHI_OK)
    return res;

  res = shishi_decrypt (handle, key, SHISHI_KEYUSAGE_KDCREP_TICKET,
			cipher, cipherlen, buf, &buflen);

  if (res != SHISHI_OK)
    {
      if (VERBOSE (handle))
	printf ("des_decrypt failed: %s\n", shishi_strerror_details (handle));
      shishi_error_printf (handle,
			   "des_decrypt fail, most likely wrong password\n");
      return SHISHI_TICKET_DECRYPT_FAILED;
    }

  /* The crypto is so 1980; no length indicator. Trim off pad bytes
     until we can parse it. */
  for (i = 0; i < 8; i++)
    {
      if (VERBOSEASN1 (handle))
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
