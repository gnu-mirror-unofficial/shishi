/* tkt.c	ticket handling
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

struct Shishi_tkt
{
  Shishi *handle;
  Shishi_asn1 ticket;
  Shishi_asn1 kdcrep;
  Shishi_asn1 enckdcreppart;
  Shishi_asn1 encticketpart;
  Shishi_key *key;
};

int
shishi_tkt_clientrealm_set (Shishi_tkt * tkt, char *realm, char *client)
{
  int res;

  res = shishi_encticketpart_crealm_set (tkt->handle,
					 tkt->encticketpart, realm);
  if (res != SHISHI_OK)
    return res;

  res = shishi_encticketpart_cname_set (tkt->handle,
					tkt->encticketpart,
					SHISHI_NT_UNKNOWN, client);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

int
shishi_tkt_serverrealm_set (Shishi_tkt * tkt, char *realm, char *server)
{
  int res;

  res = shishi_ticket_srealmserver_set (tkt->handle, tkt->ticket,
					realm, server);
  if (res != SHISHI_OK)
    return res;

  res = shishi_enckdcreppart_srealmserver_set
    (tkt->handle, tkt->enckdcreppart, realm, server);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

int
shishi_tkt_build (Shishi_tkt * tkt, Shishi_key * key)
{
  int res;

  res = shishi_ticket_add_enc_part (tkt->handle, tkt->ticket,
				    key, tkt->encticketpart);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_tkt_cname:
 * @ticket: input variable with ticket info.
 * @client: output buffer that holds client name of ticket.
 * @clientlen: on input, maximum size of output buffer,
 *             on output, actual size of output buffer.
 *
 * Return value: Returns client principal of ticket.
 **/
int
shishi_tkt_client (Shishi_tkt * tkt, char *client, int *clientlen)
{
  return shishi_principal_name_get (tkt->handle, tkt->kdcrep,
				    "cname", client, clientlen);
}

int
shishi_tkt_client_p (Shishi_tkt * tkt, const char *client)
{
  char *buf;
  int buflen;
  int res;

  buflen = strlen (client) + 1;
  buf = xmalloc (buflen);

  res = shishi_tkt_client (tkt, buf, &buflen);
  if (res != SHISHI_OK)
    {
      free (buf);
      return 0;
    }
  buf[buflen] = '\0';

  if (strcmp (client, buf) != 0)
    {
      free (buf);
      return 0;
    }

  free (buf);

  return 1;
}

int
shishi_tkt_cnamerealm (Shishi_tkt * tkt, char *cnamerealm, int *cnamerealmlen)
{
  return shishi_principal_name_realm_get (tkt->handle,
					  tkt->kdcrep, "cname",
					  tkt->kdcrep, "crealm",
					  cnamerealm, cnamerealmlen);
}

int
shishi_tkt_cnamerealm_p (Shishi_tkt * tkt, const char *client)
{
  char *buf;
  int buflen;
  int res;

  buflen = strlen (client) + 1;
  buf = xmalloc (buflen);

  res = shishi_tkt_cnamerealm (tkt, buf, &buflen);
  if (res != SHISHI_OK)
    {
      free (buf);
      return 0;
    }
  buf[buflen] = '\0';

  if (strcmp (client, buf) != 0)
    {
      free (buf);
      return 0;
    }

  free (buf);

  return 1;
}

/**
 * shishi_tkt_ticket:
 * @tkt: input variable with ticket info.
 *
 * Return value: Returns actual ticket.
 **/
Shishi_asn1
shishi_tkt_ticket (Shishi_tkt * tkt)
{
  return tkt->ticket;
}

/**
 * shishi_tkt_enckdcreppart:
 * @tkt: input variable with ticket info.
 *
 * Return value: Returns auxilliary ticket information.
 **/
Shishi_asn1
shishi_tkt_enckdcreppart (Shishi_tkt * tkt)
{
  return tkt->enckdcreppart;
}

/**
 * shishi_tkt_encticketreppart_set:
 * @as: structure that holds information about Ticket exchange
 * @enckdcreppart: EncKDCRepPart to store in Ticket.
 *
 * Set the EncKDCRepPart in the Ticket.
 **/
void
shishi_tkt_enckdcreppart_set (Shishi_tkt * tkt, Shishi_asn1 enckdcreppart)
{
  if (tkt->enckdcreppart)
    shishi_asn1_done (tkt->handle, tkt->enckdcreppart);
  tkt->enckdcreppart = enckdcreppart;
}

/**
 * shishi_tkt_kdcrep:
 * @tkt: input variable with ticket info.
 *
 * Return value: Returns KDC-REP information.
 **/
Shishi_asn1
shishi_tkt_kdcrep (Shishi_tkt * tkt)
{
  return tkt->kdcrep;
}

/**
 * shishi_tkt_encticketpart:
 * @tkt: input variable with ticket info.
 *
 * Return value: Returns EncTicketPart information.
 **/
Shishi_asn1
shishi_tkt_encticketpart (Shishi_tkt * tkt)
{
  return tkt->encticketpart;
}

/**
 * shishi_tkt_encticketpart_set:
 * @tkt: input variable with ticket info.
 * @encticketpart: encticketpart to store in ticket.
 *
 * Set the EncTicketPart in the Ticket.
 **/
void
shishi_tkt_encticketpart_set (Shishi_tkt * tkt, Shishi_asn1 encticketpart)
{
  if (tkt->encticketpart)
    shishi_asn1_done (tkt->handle, tkt->encticketpart);
  tkt->encticketpart = encticketpart;
}

/**
 * shishi_tkt_key:
 * @tkt: input variable with ticket info.
 *
 * Return value: Returns key extracted from enckdcreppart.
 **/
Shishi_key *
shishi_tkt_key (Shishi_tkt * tkt)
{
  if (!tkt->key && tkt->enckdcreppart)
    {
      int res;

      res = shishi_enckdcreppart_get_key (tkt->handle,
					  tkt->enckdcreppart, &tkt->key);
      if (res != SHISHI_OK)
	return NULL;
    }
  else if (!tkt->key && tkt->encticketpart)
    {
      int res;

      res = shishi_encticketpart_get_key (tkt->handle,
					  tkt->encticketpart, &tkt->key);
      if (res != SHISHI_OK)
	return NULL;
    }

  return tkt->key;
}

/**
 * shishi_tkt_key_set:
 * @tkt: input variable with ticket info.
 * @key: key to store in ticket.
 *
 * Set the key in the EncTicketPart.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tkt_key_set (Shishi_tkt * tkt, Shishi_key * key)
{
  int res;

  res = shishi_encticketpart_key_set (tkt->handle, tkt->encticketpart, key);
  if (res != SHISHI_OK)
    return res;

  res = shishi_enckdcreppart_key_set (tkt->handle, tkt->enckdcreppart, key);
  if (res != SHISHI_OK)
    return res;

  tkt->key = key;

  return SHISHI_OK;
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
Shishi_tkt *
shishi_tkt2 (Shishi * handle,
	     Shishi_asn1 ticket, Shishi_asn1 enckdcreppart,
	     Shishi_asn1 kdcrep)
{
  Shishi_tkt *tkt;

  tkt = xcalloc (1, sizeof (*tkt));

  tkt->handle = handle;
  tkt->ticket = ticket;
  tkt->enckdcreppart = enckdcreppart;
  tkt->kdcrep = kdcrep;

  return tkt;
}

/**
 * shishi_tkt:
 * @handle: shishi handle as allocated by shishi_init().
 * @tkt: output variable with newly allocated ticket.
 *
 * Create a new ticket handle.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tkt (Shishi * handle, Shishi_tkt ** tkt)
{
  Shishi_tkt *t;
  int res;

  t = xcalloc (1, sizeof (*t));

  t->handle = handle;

  t->ticket = shishi_asn1_ticket (handle);
  if (t->ticket == NULL)
    {
      shishi_error_printf (handle, "Could not create Ticket: %s\n",
			   shishi_error (handle));
      return SHISHI_ASN1_ERROR;
    }

  /* XXX what about tgs's? */
  t->enckdcreppart = shishi_encasreppart (handle);
  if (t->enckdcreppart == NULL)
    {
      shishi_error_printf (handle, "Could not create EncKDCRepPart: %s\n",
			   shishi_error (handle));
      return SHISHI_ASN1_ERROR;
    }

  t->encticketpart = shishi_encticketpart (handle);
  if (t->encticketpart == NULL)
    {
      shishi_error_printf (handle, "Could not create EncTicketPart: %s\n",
			   shishi_error (handle));
      return SHISHI_ASN1_ERROR;
    }

  res = shishi_encticketpart_transited_set (handle,
					    t->encticketpart,
					    SHISHI_TR_DOMAIN_X500_COMPRESS,
					    "", 0);
  if (res != SHISHI_OK)
    return res;

  res = shishi_encticketpart_authtime_set
    (handle, t->encticketpart, shishi_generalize_time (handle, time (NULL)));
  if (res != SHISHI_OK)
    return res;

  res = shishi_encticketpart_endtime_set
    (handle, t->encticketpart,
     shishi_generalize_time (handle, time (NULL) + 1000));
  if (res != SHISHI_OK)
    return res;

  t->kdcrep = shishi_asrep (handle);
  if (t->kdcrep == NULL)
    {
      shishi_error_printf (handle, "Could not create AS-REP: %s\n",
			   shishi_error (handle));
      return SHISHI_ASN1_ERROR;
    }

  *tkt = t;

  return SHISHI_OK;
}

void
shishi_tkt_done (Shishi_tkt * tkt)
{
  if (tkt->key)
    shishi_key_done (&tkt->key);
  free (tkt);
}

int
shishi_tkt_flags (Shishi_tkt * tkt, int *flags)
{
  return shishi_asn1_read_bitstring (tkt->handle, tkt->enckdcreppart,
				     "flags", flags);
}

int
shishi_tkt_flags_set (Shishi_tkt * tkt, int flags)
{
  int res;

  res = shishi_encticketpart_flags_set (tkt->handle, tkt->encticketpart,
					flags);
  if (res != SHISHI_OK)
    return res;

  res = shishi_enckdcreppart_flags_set (tkt->handle, tkt->enckdcreppart,
					flags);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

int
shishi_tkt_forwardable_p (Shishi_tkt * tkt)
{
  int flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_FORWARDABLE;
}

int
shishi_tkt_forwarded_p (Shishi_tkt * tkt)
{
  int flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_FORWARDED;
}

int
shishi_tkt_proxiable_p (Shishi_tkt * tkt)
{
  int flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_PROXIABLE;
}

int
shishi_tkt_proxy_p (Shishi_tkt * tkt)
{
  int flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_PROXY;
}

int
shishi_tkt_may_postdate_p (Shishi_tkt * tkt)
{
  int flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_MAY_POSTDATE;
}

int
shishi_tkt_postdated_p (Shishi_tkt * tkt)
{
  int flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_POSTDATED;
}

int
shishi_tkt_invalid_p (Shishi_tkt * tkt)
{
  int flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_INVALID;
}

int
shishi_tkt_renewable_p (Shishi_tkt * tkt)
{
  int flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_RENEWABLE;
}

int
shishi_tkt_initial_p (Shishi_tkt * tkt)
{
  int flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_INITIAL;
}

int
shishi_tkt_pre_authent_p (Shishi_tkt * tkt)
{
  int flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_PRE_AUTHENT;
}

int
shishi_tkt_hw_authent_p (Shishi_tkt * tkt)
{
  int flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_HW_AUTHENT;
}

int
shishi_tkt_transited_policy_checked_p (Shishi_tkt * tkt)
{
  int flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_TRANSITED_POLICY_CHECKED;
}

int
shishi_tkt_ok_as_delegate_p (Shishi_tkt * tkt)
{
  int flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_OK_AS_DELEGATE;
}

int
shishi_tkt_realm (Shishi_tkt * tkt, char **realm, size_t *realmlen)
{
  return shishi_ticket_realm_get (tkt->handle, tkt->ticket, realm, realmlen);
}

int
shishi_tkt_server (Shishi_tkt * tkt, char *server, int *serverlen)
{
  return shishi_ticket_sname_get (tkt->handle, tkt->ticket,
				  server, serverlen);
}

int
shishi_tkt_server_p (Shishi_tkt * tkt, const char *server)
{
  char *buf;
  int buflen;
  int res;

  buflen = strlen (server) + 1;
  buf = xmalloc (buflen);

  res = shishi_tkt_server (tkt, buf, &buflen);
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
shishi_tkt_server_realm (Shishi_tkt * tkt,
			 char *serverrealm, int *serverrealmlen)
{
  return shishi_ticket_snamerealm_get (tkt->handle, tkt->ticket,
				       serverrealm, serverrealmlen);
}

int
shishi_tkt_keytype (Shishi_tkt * tkt, int32_t * etype)
{
  return shishi_asn1_read_int32 (tkt->handle, tkt->enckdcreppart,
				 "key.keytype", etype);
}

int
shishi_tkt_keytype_p (Shishi_tkt * tkt, int32_t etype)
{
  int32_t tktetype;
  int rc;

  rc = shishi_asn1_read_int32 (tkt->handle, tkt->enckdcreppart,
			       "key.keytype", &tktetype);
  if (rc != SHISHI_OK)
    return 0;

  return etype == tktetype;
}

int
shishi_tkt_lastreq (Shishi_tkt * tkt,
		    char *lrtime, int *lrtimelen, int lrtype)
{
  char *format;
  int tmplrtype;
  int res;
  int i, n;

  res = shishi_asn1_number_of_elements (tkt->handle, tkt->enckdcreppart,
					"last-req", &n);
  if (res != SHISHI_OK)
    return res;

  for (i = 1; i <= n; i++)
    {
      asprintf (&format, "last-req.?%d.lr-type", i);
      res = shishi_asn1_read_integer (tkt->handle, tkt->enckdcreppart,
				      format, &tmplrtype);
      free (format);
      if (res != SHISHI_OK)
	return SHISHI_ASN1_ERROR;

      if (lrtype == tmplrtype)
	{
	  asprintf (&format, "last-req.?%d.lr-value", i);
	  res = shishi_asn1_read (tkt->handle, tkt->enckdcreppart,
				  format, lrtime, lrtimelen);
	  free (format);
	  if (res != SHISHI_OK)
	    return SHISHI_ASN1_ERROR;

	  return SHISHI_OK;
	}
    }

  return !SHISHI_OK;
}

time_t
shishi_tkt_lastreqc (Shishi_tkt * tkt, Shishi_lrtype lrtype)
{
  char lrtime[GENERALIZEDTIME_TIME_LEN + 1];
  int lrtimelen;
  time_t t;
  int res;

  lrtimelen = sizeof (lrtime);
  res = shishi_tkt_lastreq (tkt, lrtime, &lrtimelen, lrtype);
  if (res != SHISHI_OK)
    return (time_t) - 1;

  lrtime[GENERALIZEDTIME_TIME_LEN] = '\0';

  t = shishi_generalize_ctime (tkt->handle, lrtime);

  return t;
}

int
shishi_tkt_lastreq_pretty_print (Shishi_tkt * tkt, FILE * fh)
{
  time_t t;

  t = shishi_tkt_lastreqc (tkt, SHISHI_LRTYPE_LAST_INITIAL_TGT_REQUEST);
  if (t != (time_t) - 1)
    fprintf (fh, _("Time of last initial request for a TGT:\t%s"),
	     ctime (&t));

  t = shishi_tkt_lastreqc (tkt, SHISHI_LRTYPE_LAST_INITIAL_REQUEST);
  if (t != (time_t) - 1)
    fprintf (fh, "Time of last initial request:\t%s", ctime (&t));

  t = shishi_tkt_lastreqc (tkt, SHISHI_LRTYPE_NEWEST_TGT_ISSUE);
  if (t != (time_t) - 1)
    fprintf (fh,
	     "Time of issue for the newest ticket-granting ticket used:\t%s",
	     ctime (&t));

  t = shishi_tkt_lastreqc (tkt, SHISHI_LRTYPE_LAST_RENEWAL);
  if (t != (time_t) - 1)
    fprintf (fh, "Time of the last renewal:\t%s", ctime (&t));

  t = shishi_tkt_lastreqc (tkt, SHISHI_LRTYPE_LAST_REQUEST);
  if (t != (time_t) - 1)
    fprintf (fh, "Time of last request:\t%s", ctime (&t));

  return SHISHI_OK;
}

int
shishi_tkt_authtime (Shishi_tkt * tkt, char *authtime, int *authtimelen)
{
  return shishi_asn1_read (tkt->handle, tkt->enckdcreppart, "authtime",
			   authtime, authtimelen);
}

time_t
shishi_tkt_authctime (Shishi_tkt * tkt)
{
  char authtime[GENERALIZEDTIME_TIME_LEN + 1];
  int authtimelen;
  time_t t;
  int res;

  authtimelen = sizeof (authtime);
  res = shishi_tkt_authtime (tkt, authtime, &authtimelen);
  if (res != SHISHI_OK)
    return (time_t) - 1;

  authtime[GENERALIZEDTIME_TIME_LEN] = '\0';

  t = shishi_generalize_ctime (tkt->handle, authtime);

  return t;
}

int
shishi_tkt_starttime (Shishi_tkt * tkt, char *starttime, int *starttimelen)
{
  return shishi_asn1_read_optional (tkt->handle, tkt->enckdcreppart,
				    "starttime", starttime, starttimelen);
}

time_t
shishi_tkt_startctime (Shishi_tkt * tkt)
{
  char starttime[GENERALIZEDTIME_TIME_LEN + 1];
  int starttimelen;
  time_t t;
  int res;

  starttimelen = sizeof (starttime);
  res = shishi_tkt_starttime (tkt, starttime, &starttimelen);
  if (res != SHISHI_OK || starttimelen == 0)
    return (time_t) - 1;

  starttime[GENERALIZEDTIME_TIME_LEN] = '\0';

  t = shishi_generalize_ctime (tkt->handle, starttime);

  return t;
}

int
shishi_tkt_endtime (Shishi_tkt * tkt, char *endtime, int *endtimelen)
{
  return shishi_asn1_read (tkt->handle, tkt->enckdcreppart, "endtime",
			   endtime, endtimelen);
}

time_t
shishi_tkt_endctime (Shishi_tkt * tkt)
{
  char endtime[GENERALIZEDTIME_TIME_LEN + 1];
  int endtimelen;
  time_t t;
  int res;

  endtimelen = sizeof (endtime);
  res = shishi_tkt_endtime (tkt, endtime, &endtimelen);
  if (res != SHISHI_OK)
    return (time_t) - 1;

  endtime[GENERALIZEDTIME_TIME_LEN] = '\0';

  t = shishi_generalize_ctime (tkt->handle, endtime);

  return t;
}

int
shishi_tkt_renew_till (Shishi_tkt * tkt, char *renewtill, int *renewtilllen)
{
  return shishi_asn1_read_optional (tkt->handle, tkt->enckdcreppart,
				    "renew-till", renewtill, renewtilllen);
}

time_t
shishi_tkt_renew_tillc (Shishi_tkt * tkt)
{
  char renewtill[GENERALIZEDTIME_TIME_LEN + 1];
  int renewtilllen;
  time_t t;
  int res;

  renewtilllen = sizeof (renewtill);
  res = shishi_tkt_renew_till (tkt, renewtill, &renewtilllen);
  if (res != SHISHI_OK || renewtilllen == 0)
    return (time_t) - 1;

  renewtill[GENERALIZEDTIME_TIME_LEN] = '\0';

  t = shishi_generalize_ctime (tkt->handle, renewtill);

  return t;
}

int
shishi_tkt_valid_at_time_p (Shishi_tkt * tkt, time_t now)
{
  time_t starttime, endtime;

  starttime = shishi_tkt_startctime (tkt);
  if (starttime == (time_t) - 1)
    starttime = shishi_tkt_authctime (tkt);
  endtime = shishi_tkt_endctime (tkt);

  return starttime <= now && now <= endtime;
}

int
shishi_tkt_valid_now_p (Shishi_tkt * tkt)
{
  return shishi_tkt_valid_at_time_p (tkt, time (NULL));
}

int
shishi_tkt_pretty_print (Shishi_tkt * tkt, FILE * fh)
{
  char buf[BUFSIZ];
  char *p;
  int buflen;
  int keytype, etype, flags;
  int res;
  time_t t;

  buflen = sizeof (buf);
  buf[0] = '\0';
  res = shishi_tkt_cnamerealm (tkt, buf, &buflen);
  if (res != SHISHI_OK)
    return res;
  buf[buflen] = '\0';
  fprintf (fh, "%s:\n", buf);

  t = shishi_tkt_authctime (tkt);
  fprintf (fh, _("Acquired:\t%s"), ctime (&t));

  t = shishi_tkt_startctime (tkt);
  if (t != (time_t) - 1)
    fprintf (fh, _("Valid from:\t%s"), ctime (&t));

  t = shishi_tkt_endctime (tkt);
  p = ctime (&t);
  p[strlen (p) - 1] = '\0';
  fprintf (fh, _("Expires:\t%s"), p);
  if (!shishi_tkt_valid_now_p (tkt))
    fprintf (fh, " (EXPIRED)");
  fprintf (fh, "\n");

  t = shishi_tkt_renew_tillc (tkt);
  if (t != (time_t) - 1)
    fprintf (fh, _("Renewable till:\t%s"), ctime (&t));

  buflen = sizeof (buf);
  buf[0] = '\0';
  res = shishi_tkt_server (tkt, buf, &buflen);
  if (res != SHISHI_OK)
    return res;
  buf[buflen] = '\0';
  res = shishi_ticket_get_enc_part_etype (tkt->handle, tkt->ticket, &keytype);
  if (res != SHISHI_OK)
    return res;
  fprintf (fh, _("Server:\t\t%s key %s (%d)\n"), buf,
	   shishi_cipher_name (keytype), keytype);

  res = shishi_tkt_keytype (tkt, &keytype);
  if (res != SHISHI_OK)
    return res;
  res = shishi_kdcrep_get_enc_part_etype (tkt->handle, tkt->kdcrep, &etype);
  if (res != SHISHI_OK)
    return res;
  fprintf (fh, _("Ticket key:\t%s (%d) protected by %s (%d)\n"),
	   shishi_cipher_name (keytype), keytype,
	   shishi_cipher_name (etype), etype);


  res = shishi_tkt_flags (tkt, &flags);
  if (res != SHISHI_OK)
    return res;
  if (flags)
    {
      fprintf (fh, _("Ticket flags:\t"));
      if (shishi_tkt_forwardable_p (tkt))
	fprintf (fh, "FORWARDABLE ");
      if (shishi_tkt_forwarded_p (tkt))
	fprintf (fh, "FORWARDED ");
      if (shishi_tkt_proxiable_p (tkt))
	fprintf (fh, "PROXIABLE ");
      if (shishi_tkt_proxy_p (tkt))
	fprintf (fh, "PROXY ");
      if (shishi_tkt_may_postdate_p (tkt))
	fprintf (fh, "MAYPOSTDATE ");
      if (shishi_tkt_postdated_p (tkt))
	fprintf (fh, "POSTDATED ");
      if (shishi_tkt_invalid_p (tkt))
	fprintf (fh, "INVALID ");
      if (shishi_tkt_renewable_p (tkt))
	fprintf (fh, "RENEWABLE ");
      if (shishi_tkt_initial_p (tkt))
	fprintf (fh, "INITIAL ");
      if (shishi_tkt_pre_authent_p (tkt))
	fprintf (fh, "PREAUTHENT ");
      if (shishi_tkt_hw_authent_p (tkt))
	fprintf (fh, "HWAUTHENT ");
      if (shishi_tkt_transited_policy_checked_p (tkt))
	fprintf (fh, "TRANSITEDPOLICYCHECKED ");
      if (shishi_tkt_ok_as_delegate_p (tkt))
	fprintf (fh, "OKASDELEGATE ");
      fprintf (fh, "(%d)\n", flags);
    }

  return SHISHI_OK;
}

int
shishi_tkt_decrypt (Shishi_tkt * tkt, Shishi_key * key)
{
  int rc;
  Shishi_asn1 encticketpart;

  rc = shishi_ticket_decrypt (tkt->handle, tkt->ticket, key, &encticketpart);
  if (rc != SHISHI_OK)
    return rc;

  tkt->encticketpart = encticketpart;

  return SHISHI_OK;
}
