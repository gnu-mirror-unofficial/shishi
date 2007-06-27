/* tkt.c --- Ticket handling.
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

  t->ticket = shishi_ticket (handle);
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

  /* XXX We don't allocate t->key here, because shishi_tkt_key()
     relies on it being NULL.  Possibly, we should allocate it here
     instead, and simplify shishi_tkt_key().  */

  *tkt = t;

  return SHISHI_OK;
}

/**
 * shishi_tkt2:
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
 * shishi_tkt_done:
 * @tkt: input variable with ticket info.
 *
 * Deallocate resources associated with ticket.  The ticket must not
 * be used again after this call.
 **/
void
shishi_tkt_done (Shishi_tkt * tkt)
{
  if (tkt->key)
    shishi_key_done (tkt->key);
  free (tkt);
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
 * shishi_tkt_ticket:
 * @tkt: input variable with ticket info.
 *
 * Get ASN.1 Ticket structure from ticket.
 *
 * Return value: Returns actual ticket.
 **/
Shishi_asn1
shishi_tkt_ticket (Shishi_tkt * tkt)
{
  return tkt->ticket;
}

/**
 * shishi_tkt_ticket_set:
 * @tkt: input variable with ticket info.
 * @ticket: ASN.1 Ticket to store in ticket.
 *
 * Set the ASN.1 Ticket in the Ticket.
 **/
void
shishi_tkt_ticket_set (Shishi_tkt * tkt, Shishi_asn1 ticket)
{
  if (tkt->ticket)
    shishi_asn1_done (tkt->handle, tkt->ticket);
  tkt->ticket = ticket;
}

/**
 * shishi_tkt_enckdcreppart:
 * @tkt: input variable with ticket info.
 *
 * Get ASN.1 EncKDCRepPart structure from ticket.
 *
 * Return value: Returns auxilliary ticket information.
 **/
Shishi_asn1
shishi_tkt_enckdcreppart (Shishi_tkt * tkt)
{
  return tkt->enckdcreppart;
}

/**
 * shishi_tkt_enckdcreppart_set:
 * @tkt: structure that holds information about Ticket exchange
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
 * Get ASN.1 KDCRep structure from ticket.
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
 * Get ASN.1 EncTicketPart structure from ticket.
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
 * Get key used in ticket, by looking first in EncKDCRepPart and then
 * in EncTicketPart.  If key is already populated, it is not extracted
 * again.
 *
 * Return value: Returns key extracted from EncKDCRepPart or
 * EncTicketPart.
 **/
Shishi_key *
shishi_tkt_key (Shishi_tkt * tkt)
{
  int rc;

  /* XXX We probably shouldn't extract the keys here.  Where is this
     extraction actually needed?  */
  if (!tkt->key && tkt->enckdcreppart)
    {
      rc = shishi_enckdcreppart_get_key (tkt->handle,
					 tkt->enckdcreppart, &tkt->key);
      if (rc != SHISHI_OK)
	return NULL;
    }
  else if (!tkt->key && tkt->encticketpart)
    {
      rc = shishi_encticketpart_get_key (tkt->handle,
					 tkt->encticketpart, &tkt->key);
      if (rc != SHISHI_OK)
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

  if (!tkt->key)
    {
      res = shishi_key (tkt->handle, &tkt->key);
      if (res != SHISHI_OK)
	return res;
    }

  shishi_key_copy (tkt->key, key);

  return SHISHI_OK;
}

int
shishi_tkt_clientrealm_set (Shishi_tkt * tkt,
			    const char *realm, const char *client)
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
shishi_tkt_serverrealm_set (Shishi_tkt * tkt,
			    const char *realm, const char *server)
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

/**
 * shishi_tkt_client:
 * @tkt: input variable with ticket info.
 * @client: pointer to newly allocated zero terminated string containing
 *   principal name.  May be %NULL (to only populate @clientlen).
 * @clientlen: pointer to length of @client on output, excluding terminating
 *   zero.  May be %NULL (to only populate @client).
 *
 * Represent client principal name in Ticket KDC-REP as
 * zero-terminated string.  The string is allocate by this function,
 * and it is the responsibility of the caller to deallocate it.  Note
 * that the output length @clientlen does not include the terminating
 * zero.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tkt_client (Shishi_tkt * tkt, char **client, size_t * clientlen)
{
  return shishi_principal_name (tkt->handle, tkt->kdcrep,
				"cname", client, clientlen);
}

/**
 * shishi_tkt_client_p:
 * @tkt: input variable with ticket info.
 * @client: client name of ticket.
 *
 * Determine if ticket is for specified client.
 *
 * Return value: Returns non-0 iff ticket is for specified client.
 **/
int
shishi_tkt_client_p (Shishi_tkt * tkt, const char *client)
{
  char *buf;
  size_t buflen;
  int res;

  res = shishi_tkt_client (tkt, &buf, &buflen);
  if (res != SHISHI_OK)
    return 0;

  res = strcmp (client, buf) == 0;

  free (buf);

  return res;
}

/**
 * shishi_tkt_clientrealm:
 * @tkt: input variable with ticket info.
 * @client: pointer to newly allocated zero terminated string containing
 *   principal name and realm.  May be %NULL (to only populate @clientlen).
 * @clientlen: pointer to length of @client on output, excluding terminating
 *   zero.  May be %NULL (to only populate @client).
 *
 * Convert cname and realm fields from AS-REQ to printable principal
 * name format.  The string is allocate by this function, and it is
 * the responsibility of the caller to deallocate it.  Note that the
 * output length @clientlen does not include the terminating zero.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tkt_clientrealm (Shishi_tkt * tkt, char **client, size_t * clientlen)
{
  return shishi_principal_name_realm (tkt->handle,
				      tkt->kdcrep, "cname",
				      tkt->kdcrep, "crealm",
				      client, clientlen);
}

/**
 * shishi_tkt_clientrealm_p:
 * @tkt: input variable with ticket info.
 * @client: principal name (client name and realm) of ticket.
 *
 * Determine if ticket is for specified client principal.
 *
 * Return value: Returns non-0 iff ticket is for specified client principal.
 **/
int
shishi_tkt_clientrealm_p (Shishi_tkt * tkt, const char *client)
{
  char *buf;
  size_t buflen;
  int res;

  res = shishi_tkt_clientrealm (tkt, &buf, &buflen);
  if (res != SHISHI_OK)
    return 0;

  res = strcmp (client, buf) == 0;

  free (buf);

  return res;
}

/**
 * shishi_tkt_realm:
 * @tkt: input variable with ticket info.
 * @realm: pointer to newly allocated character array with realm name.
 * @realmlen: length of newly allocated character array with realm name.
 *
 * Extract realm of server in ticket.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tkt_realm (Shishi_tkt * tkt, char **realm, size_t * realmlen)
{
  return shishi_ticket_realm_get (tkt->handle, tkt->ticket, realm, realmlen);
}

/**
 * shishi_tkt_server:
 * @tkt: input variable with ticket info.
 * @server: pointer to newly allocated zero terminated string containing
 *   principal name.  May be %NULL (to only populate @serverlen).
 * @serverlen: pointer to length of @server on output, excluding terminating
 *   zero.  May be %NULL (to only populate @server).
 *
 * Represent server principal name in Ticket as zero-terminated
 * string.  The string is allocate by this function, and it is the
 * responsibility of the caller to deallocate it.  Note that the
 * output length @serverlen does not include the terminating zero.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tkt_server (Shishi_tkt * tkt, char **server, size_t * serverlen)
{
  return shishi_ticket_server (tkt->handle, tkt->ticket, server, serverlen);
}

/**
 * shishi_tkt_server_p:
 * @tkt: input variable with ticket info.
 * @server: server name of ticket.
 *
 * Determine if ticket is for specified server.
 *
 * Return value: Returns non-0 iff ticket is for specified server.
 **/
int
shishi_tkt_server_p (Shishi_tkt * tkt, const char *server)
{
  char *buf;
  int res;

  res = shishi_tkt_server (tkt, &buf, NULL);
  if (res != SHISHI_OK)
    return 0;

  res = strcmp (server, buf) == 0;

  free (buf);

  return res;
}

/**
 * shishi_tkt_flags:
 * @tkt: input variable with ticket info.
 * @flags: pointer to output integer with flags.
 *
 * Extract flags in ticket (i.e., EncKDCRepPart).
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tkt_flags (Shishi_tkt * tkt, uint32_t * flags)
{
  return shishi_asn1_read_bitstring (tkt->handle, tkt->enckdcreppart,
				     "flags", flags);
}

/**
 * shishi_tkt_flags_set:
 * @tkt: input variable with ticket info.
 * @flags: integer with flags to store in ticket.
 *
 * Set flags in ticket, i.e., both EncTicketPart and EncKDCRepPart.
 * Note that this reset any already existing flags.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tkt_flags_set (Shishi_tkt * tkt, uint32_t flags)
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

/**
 * shishi_tkt_flags_add:
 * @tkt: input variable with ticket info.
 * @flag: integer with flags to store in ticket.
 *
 * Add ticket flags to Ticket and EncKDCRepPart.  This preserves all
 * existing options.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tkt_flags_add (Shishi_tkt * tkt, uint32_t flag)
{
  uint32_t flags;
  int res;

  res = shishi_tkt_flags (tkt, &flags);
  if (res != SHISHI_OK)
    return res;

  flags |= flag;

  res = shishi_tkt_flags_set (tkt, flags);
  if (res != SHISHI_OK)
    return res;

  return SHISHI_OK;
}

/**
 * shishi_tkt_forwardable_p:
 * @tkt: input variable with ticket info.
 *
 * Determine if ticket is forwardable.
 *
 * The FORWARDABLE flag in a ticket is normally only interpreted by
 * the ticket-granting service. It can be ignored by application
 * servers.  The FORWARDABLE flag has an interpretation similar to
 * that of the PROXIABLE flag, except ticket-granting tickets may also
 * be issued with different network addresses. This flag is reset by
 * default, but users MAY request that it be set by setting the
 * FORWARDABLE option in the AS request when they request their
 * initial ticket-granting ticket.
 *
 * Return value: Returns non-0 iff forwardable flag is set in ticket.
 **/
int
shishi_tkt_forwardable_p (Shishi_tkt * tkt)
{
  uint32_t flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_FORWARDABLE;
}

/**
 * shishi_tkt_forwarded_p:
 * @tkt: input variable with ticket info.
 *
 * Determine if ticket is forwarded.
 *
 * The FORWARDED flag is set by the TGS when a client presents a
 * ticket with the FORWARDABLE flag set and requests a forwarded
 * ticket by specifying the FORWARDED KDC option and supplying a set
 * of addresses for the new ticket. It is also set in all tickets
 * issued based on tickets with the FORWARDED flag set. Application
 * servers may choose to process FORWARDED tickets differently than
 * non-FORWARDED tickets.
 *
 * Return value: Returns non-0 iff forwarded flag is set in ticket.
 **/
int
shishi_tkt_forwarded_p (Shishi_tkt * tkt)
{
  uint32_t flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_FORWARDED;
}

/**
 * shishi_tkt_proxiable_p:
 * @tkt: input variable with ticket info.
 *
 * Determine if ticket is proxiable.
 *
 * The PROXIABLE flag in a ticket is normally only interpreted by the
 * ticket-granting service. It can be ignored by application servers.
 * When set, this flag tells the ticket-granting server that it is OK
 * to issue a new ticket (but not a ticket-granting ticket) with a
 * different network address based on this ticket. This flag is set if
 * requested by the client on initial authentication. By default, the
 * client will request that it be set when requesting a
 * ticket-granting ticket, and reset when requesting any other ticket.
 *
 * Return value: Returns non-0 iff proxiable flag is set in ticket.
 **/
int
shishi_tkt_proxiable_p (Shishi_tkt * tkt)
{
  uint32_t flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_PROXIABLE;
}

/**
 * shishi_tkt_proxy_p:
 * @tkt: input variable with ticket info.
 *
 * Determine if ticket is proxy ticket.
 *
 * The PROXY flag is set in a ticket by the TGS when it issues a proxy
 * ticket.  Application servers MAY check this flag and at their
 * option they MAY require additional authentication from the agent
 * presenting the proxy in order to provide an audit trail.
 *
 * Return value: Returns non-0 iff proxy flag is set in ticket.
 **/
int
shishi_tkt_proxy_p (Shishi_tkt * tkt)
{
  uint32_t flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_PROXY;
}

/**
 * shishi_tkt_may_postdate_p:
 * @tkt: input variable with ticket info.
 *
 * Determine if ticket may be used to grant postdated tickets.
 *
 * The MAY-POSTDATE flag in a ticket is normally only interpreted by
 * the ticket-granting service. It can be ignored by application
 * servers.  This flag MUST be set in a ticket-granting ticket in
 * order to issue a postdated ticket based on the presented ticket. It
 * is reset by default; it MAY be requested by a client by setting the
 * ALLOW- POSTDATE option in the KRB_AS_REQ message.  This flag does
 * not allow a client to obtain a postdated ticket-granting ticket;
 * postdated ticket-granting tickets can only by obtained by
 * requesting the postdating in the KRB_AS_REQ message. The life
 * (endtime-starttime) of a postdated ticket will be the remaining
 * life of the ticket-granting ticket at the time of the request,
 * unless the RENEWABLE option is also set, in which case it can be
 * the full life (endtime-starttime) of the ticket-granting
 * ticket. The KDC MAY limit how far in the future a ticket may be
 * postdated.
 *
 * Return value: Returns non-0 iff may-postdate flag is set in ticket.
 **/
int
shishi_tkt_may_postdate_p (Shishi_tkt * tkt)
{
  uint32_t flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_MAY_POSTDATE;
}

/**
 * shishi_tkt_postdated_p:
 * @tkt: input variable with ticket info.
 *
 * Determine if ticket is postdated.
 *
 * The POSTDATED flag indicates that a ticket has been postdated. The
 * application server can check the authtime field in the ticket to
 * see when the original authentication occurred. Some services MAY
 * choose to reject postdated tickets, or they may only accept them
 * within a certain period after the original authentication. When the
 * KDC issues a POSTDATED ticket, it will also be marked as INVALID,
 * so that the application client MUST present the ticket to the KDC
 * to be validated before use.
 *
 * Return value: Returns non-0 iff postdated flag is set in ticket.
 **/
int
shishi_tkt_postdated_p (Shishi_tkt * tkt)
{
  uint32_t flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_POSTDATED;
}

/**
 * shishi_tkt_invalid_p:
 * @tkt: input variable with ticket info.
 *
 * Determine if ticket is invalid.
 *
 * The INVALID flag indicates that a ticket is invalid. Application
 * servers MUST reject tickets which have this flag set. A postdated
 * ticket will be issued in this form. Invalid tickets MUST be
 * validated by the KDC before use, by presenting them to the KDC in a
 * TGS request with the VALIDATE option specified. The KDC will only
 * validate tickets after their starttime has passed. The validation
 * is required so that postdated tickets which have been stolen before
 * their starttime can be rendered permanently invalid (through a
 * hot-list mechanism).
 *
 * Return value: Returns non-0 iff invalid flag is set in ticket.
 **/
int
shishi_tkt_invalid_p (Shishi_tkt * tkt)
{
  uint32_t flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_INVALID;
}

/**
 * shishi_tkt_renewable_p:
 * @tkt: input variable with ticket info.
 *
 * Determine if ticket is renewable.
 *
 * The RENEWABLE flag in a ticket is normally only interpreted by the
 * ticket-granting service (discussed below in section 3.3). It can
 * usually be ignored by application servers. However, some
 * particularly careful application servers MAY disallow renewable
 * tickets.
 *
 * Return value: Returns non-0 iff renewable flag is set in ticket.
 **/
int
shishi_tkt_renewable_p (Shishi_tkt * tkt)
{
  uint32_t flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_RENEWABLE;
}

/**
 * shishi_tkt_initial_p:
 * @tkt: input variable with ticket info.
 *
 * Determine if ticket was issued using AS exchange.
 *
 * The INITIAL flag indicates that a ticket was issued using the AS
 * protocol, rather than issued based on a ticket-granting ticket.
 * Application servers that want to require the demonstrated knowledge
 * of a client's secret key (e.g. a password-changing program) can
 * insist that this flag be set in any tickets they accept, and thus
 * be assured that the client's key was recently presented to the
 * application client.
 *
 * Return value: Returns non-0 iff initial flag is set in ticket.
 **/
int
shishi_tkt_initial_p (Shishi_tkt * tkt)
{
  uint32_t flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_INITIAL;
}

/**
 * shishi_tkt_pre_authent_p:
 * @tkt: input variable with ticket info.
 *
 * Determine if ticket was pre-authenticated.
 *
 * The PRE-AUTHENT and HW-AUTHENT flags provide additional information
 * about the initial authentication, regardless of whether the current
 * ticket was issued directly (in which case INITIAL will also be set)
 * or issued on the basis of a ticket-granting ticket (in which case
 * the INITIAL flag is clear, but the PRE-AUTHENT and HW-AUTHENT flags
 * are carried forward from the ticket-granting ticket).
 *
 * Return value: Returns non-0 iff pre-authent flag is set in ticket.
 **/
int
shishi_tkt_pre_authent_p (Shishi_tkt * tkt)
{
  uint32_t flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_PRE_AUTHENT;
}

/**
 * shishi_tkt_hw_authent_p:
 * @tkt: input variable with ticket info.
 *
 * Determine if ticket is authenticated using a hardware token.
 *
 * The PRE-AUTHENT and HW-AUTHENT flags provide additional information
 * about the initial authentication, regardless of whether the current
 * ticket was issued directly (in which case INITIAL will also be set)
 * or issued on the basis of a ticket-granting ticket (in which case
 * the INITIAL flag is clear, but the PRE-AUTHENT and HW-AUTHENT flags
 * are carried forward from the ticket-granting ticket).
 *
 * Return value: Returns non-0 iff hw-authent flag is set in ticket.
 **/
int
shishi_tkt_hw_authent_p (Shishi_tkt * tkt)
{
  uint32_t flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_HW_AUTHENT;
}

/**
 * shishi_tkt_transited_policy_checked_p:
 * @tkt: input variable with ticket info.
 *
 * Determine if ticket has been policy checked for transit.
 *
 * The application server is ultimately responsible for accepting or
 * rejecting authentication and SHOULD check that only suitably
 * trusted KDCs are relied upon to authenticate a principal.  The
 * transited field in the ticket identifies which realms (and thus
 * which KDCs) were involved in the authentication process and an
 * application server would normally check this field. If any of these
 * are untrusted to authenticate the indicated client principal
 * (probably determined by a realm-based policy), the authentication
 * attempt MUST be rejected. The presence of trusted KDCs in this list
 * does not provide any guarantee; an untrusted KDC may have
 * fabricated the list.
 *
 * While the end server ultimately decides whether authentication is
 * valid, the KDC for the end server's realm MAY apply a realm
 * specific policy for validating the transited field and accepting
 * credentials for cross-realm authentication. When the KDC applies
 * such checks and accepts such cross-realm authentication it will set
 * the TRANSITED-POLICY-CHECKED flag in the service tickets it issues
 * based on the cross-realm TGT. A client MAY request that the KDCs
 * not check the transited field by setting the
 * DISABLE-TRANSITED-CHECK flag. KDCs are encouraged but not required
 * to honor this flag.
 *
 * Application servers MUST either do the transited-realm checks
 * themselves, or reject cross-realm tickets without TRANSITED-POLICY-
 * CHECKED set.
 *
 * Return value: Returns non-0 iff transited-policy-checked flag is
 *   set in ticket.
 **/
int
shishi_tkt_transited_policy_checked_p (Shishi_tkt * tkt)
{
  uint32_t flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_TRANSITED_POLICY_CHECKED;
}

/**
 * shishi_tkt_ok_as_delegate_p:
 * @tkt: input variable with ticket info.
 *
 * Determine if ticket is ok as delegated ticket.
 *
 * The copy of the ticket flags in the encrypted part of the KDC reply
 * may have the OK-AS-DELEGATE flag set to indicates to the client
 * that the server specified in the ticket has been determined by
 * policy of the realm to be a suitable recipient of delegation.  A
 * client can use the presence of this flag to help it make a decision
 * whether to delegate credentials (either grant a proxy or a
 * forwarded ticket- granting ticket) to this server.  It is
 * acceptable to ignore the value of this flag. When setting this
 * flag, an administrator should consider the security and placement
 * of the server on which the service will run, as well as whether the
 * service requires the use of delegated credentials.
 *
 * Return value: Returns non-0 iff ok-as-delegate flag is set in ticket.
 **/
int
shishi_tkt_ok_as_delegate_p (Shishi_tkt * tkt)
{
  uint32_t flags = 0;

  shishi_tkt_flags (tkt, &flags);

  return flags & SHISHI_TICKETFLAGS_OK_AS_DELEGATE;
}

/**
 * shishi_tkt_keytype:
 * @tkt: input variable with ticket info.
 * @etype: pointer to encryption type that is set, see Shishi_etype.
 *
 * Extract encryption type of key in ticket (really EncKDCRepPart).
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_tkt_keytype (Shishi_tkt * tkt, int32_t * etype)
{
  return shishi_asn1_read_int32 (tkt->handle, tkt->enckdcreppart,
				 "key.keytype", etype);
}

/**
 * shishi_tkt_keytype_fast:
 * @tkt: input variable with ticket info.
 *
 * Extract encryption type of key in ticket (really EncKDCRepPart).
 *
 * Return value: Returns encryption type of session key in ticket
 *   (really EncKDCRepPart), or -1 on error.
 **/
int32_t
shishi_tkt_keytype_fast (Shishi_tkt * tkt)
{
  int32_t etype = -1;
  int res;

  res = shishi_asn1_read_int32 (tkt->handle, tkt->enckdcreppart,
				"key.keytype", &etype);
  if (res != SHISHI_OK)
    return -1;

  return etype;
}

/**
 * shishi_tkt_keytype_p:
 * @tkt: input variable with ticket info.
 * @etype: encryption type, see Shishi_etype.
 *
 * Determine if key in ticket (really EncKDCRepPart) is of specified
 * key type (really encryption type).
 *
 * Return value: Returns non-0 iff key in ticket is of specified
 *   encryption type.
 **/
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
		    char **lrtime, size_t * lrtimelen, int32_t lrtype)
{
  char *format;
  int32_t tmplrtype;
  size_t i, n;
  int res;

  res = shishi_asn1_number_of_elements (tkt->handle, tkt->enckdcreppart,
					"last-req", &n);
  if (res != SHISHI_OK)
    return res;

  for (i = 1; i <= n; i++)
    {
      asprintf (&format, "last-req.?%d.lr-type", i);
      res = shishi_asn1_read_int32 (tkt->handle, tkt->enckdcreppart,
				    format, &tmplrtype);
      free (format);
      if (res != SHISHI_OK)
	return res;

      if (lrtype == tmplrtype)
	{
	  asprintf (&format, "last-req.?%d.lr-value", i);
	  res = shishi_asn1_read (tkt->handle, tkt->enckdcreppart,
				  format, lrtime, lrtimelen);
	  free (format);
	  if (res != SHISHI_OK)
	    return res;

	  return SHISHI_OK;
	}
    }

  return !SHISHI_OK;
}

/**
 * shishi_tkt_lastreqc:
 * @tkt: input variable with ticket info.
 * @lrtype: lastreq type to extract, see Shishi_lrtype.  E.g.,
 *   SHISHI_LRTYPE_LAST_REQUEST.
 *
 * Extract C time corresponding to given lastreq type field in the
 * ticket.
 *
 * Return value: Returns C time interpretation of the specified
 *   lastreq field, or (time_t) -1.
 **/
time_t
shishi_tkt_lastreqc (Shishi_tkt * tkt, Shishi_lrtype lrtype)
{
  char *lrtime;
  size_t lrtimelen;
  time_t t = (time_t) - 1;
  int res;

  res = shishi_tkt_lastreq (tkt, &lrtime, &lrtimelen, lrtype);
  if (res != SHISHI_OK)
    return t;

  if (lrtimelen == SHISHI_GENERALIZEDTIME_LENGTH)
    t = shishi_generalize_ctime (tkt->handle, lrtime);

  free (lrtime);

  return t;
}

int
shishi_tkt_authtime (Shishi_tkt * tkt, char **authtime, size_t * authtimelen)
{
  return shishi_asn1_read (tkt->handle, tkt->enckdcreppart, "authtime",
			   authtime, authtimelen);
}

/**
 * shishi_tkt_authctime:
 * @tkt: input variable with ticket info.
 *
 * Extract C time corresponding to the authtime field.  The field
 * holds the time when the original authentication took place that
 * later resulted in this ticket.
 *
 * Return value: Returns C time interpretation of the endtime in ticket.
 **/
time_t
shishi_tkt_authctime (Shishi_tkt * tkt)
{
  char *authtime;
  size_t authtimelen;
  time_t t = (time_t) - 1;
  int res;

  res = shishi_tkt_authtime (tkt, &authtime, &authtimelen);
  if (res != SHISHI_OK)
    return t;

  if (authtimelen == SHISHI_GENERALIZEDTIME_LENGTH + 1)	/* XXX why +1 ? */
    t = shishi_generalize_ctime (tkt->handle, authtime);

  free (authtime);

  return t;
}

int
shishi_tkt_starttime (Shishi_tkt * tkt,
		      char **starttime, size_t * starttimelen)
{
  return shishi_asn1_read_optional (tkt->handle, tkt->enckdcreppart,
				    "starttime", starttime, starttimelen);
}

/**
 * shishi_tkt_startctime:
 * @tkt: input variable with ticket info.
 *
 * Extract C time corresponding to the starttime field.  The field
 * holds the time where the ticket start to be valid (typically in the
 * past).
 *
 * Return value: Returns C time interpretation of the endtime in ticket.
 **/
time_t
shishi_tkt_startctime (Shishi_tkt * tkt)
{
  char *starttime;
  size_t starttimelen;
  time_t t = (time_t) - 1;
  int res;

  res = shishi_tkt_starttime (tkt, &starttime, &starttimelen);
  if (res != SHISHI_OK || starttimelen == 0)
    return t;

  if (starttimelen == SHISHI_GENERALIZEDTIME_LENGTH + 1)	/* XXX why +1 ? */
    t = shishi_generalize_ctime (tkt->handle, starttime);

  free (starttime);

  return t;
}

int
shishi_tkt_endtime (Shishi_tkt * tkt, char **endtime, size_t * endtimelen)
{
  return shishi_asn1_read (tkt->handle, tkt->enckdcreppart, "endtime",
			   endtime, endtimelen);
}

/**
 * shishi_tkt_endctime:
 * @tkt: input variable with ticket info.
 *
 * Extract C time corresponding to the endtime field.  The field holds
 * the time where the ticket stop being valid.
 *
 * Return value: Returns C time interpretation of the endtime in ticket.
 **/
time_t
shishi_tkt_endctime (Shishi_tkt * tkt)
{
  char *endtime;
  size_t endtimelen;
  time_t t = (time_t) - 1;
  int res;

  res = shishi_tkt_endtime (tkt, &endtime, &endtimelen);
  if (res != SHISHI_OK)
    return t;

  if (endtimelen == SHISHI_GENERALIZEDTIME_LENGTH + 1)	/* XXX why +1 ? */
    t = shishi_generalize_ctime (tkt->handle, endtime);

  free (endtime);

  return t;
}

int
shishi_tkt_renew_till (Shishi_tkt * tkt,
		       char **renewtill, size_t * renewtilllen)
{
  return shishi_asn1_read_optional (tkt->handle, tkt->enckdcreppart,
				    "renew-till", renewtill, renewtilllen);
}

/**
 * shishi_tkt_renew_tillc:
 * @tkt: input variable with ticket info.
 *
 * Extract C time corresponding to the renew-till field.  The field
 * holds the time where the ticket stop being valid for renewal.
 *
 * Return value: Returns C time interpretation of the renew-till in ticket.
 **/
time_t
shishi_tkt_renew_tillc (Shishi_tkt * tkt)
{
  char *renewtill;
  size_t renewtilllen;
  time_t t = (time_t) - 1;
  int res;

  res = shishi_tkt_renew_till (tkt, &renewtill, &renewtilllen);
  if (res != SHISHI_OK || renewtilllen == 0)
    return t;

  if (renewtilllen == SHISHI_GENERALIZEDTIME_LENGTH + 1)	/* XXX why +1 ? */
    t = shishi_generalize_ctime (tkt->handle, renewtill);

  free (renewtill);

  return t;
}

/**
 * shishi_tkt_valid_at_time_p:
 * @tkt: input variable with ticket info.
 * @now: time to check for.
 *
 * Determine if ticket is valid at a specific point in time.
 *
 * Return value: Returns non-0 iff ticket is valid (not expired and
 *   after starttime) at specified time.
 **/
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

/**
 * shishi_tkt_valid_now_p:
 * @tkt: input variable with ticket info.
 *
 * Determine if ticket is valid now.
 *
 * Return value: Returns 0 iff ticket is invalid (expired or not yet
 *   valid).
 **/
int
shishi_tkt_valid_now_p (Shishi_tkt * tkt)
{
  return shishi_tkt_valid_at_time_p (tkt, time (NULL));
}

/**
 * shishi_tkt_expired_p:
 * @tkt: input variable with ticket info.
 *
 * Determine if ticket has expired (i.e., endtime is in the past).
 *
 * Return value: Returns 0 iff ticket has expired.
 **/
int
shishi_tkt_expired_p (Shishi_tkt * tkt)
{
  time_t endtime = shishi_tkt_endctime (tkt);
  time_t now = time (NULL);

  return endtime < now;
}

/**
 * shishi_tkt_lastreq_pretty_print:
 * @tkt: input variable with ticket info.
 * @fh: file handle open for writing.
 *
 * Print a human readable representation of the various lastreq fields
 * in the ticket (really EncKDCRepPart).
 **/
void
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
}

/**
 * shishi_tkt_pretty_print:
 * @tkt: input variable with ticket info.
 * @fh: file handle open for writing.
 *
 * Print a human readable representation of a ticket to file handle.
 **/
void
shishi_tkt_pretty_print (Shishi_tkt * tkt, FILE * fh)
{
  char *buf;
  char *p;
  size_t buflen;
  int keytype, etype;
  uint32_t flags;
  int res;
  time_t t;
  time_t now = time (NULL);

  res = shishi_tkt_clientrealm (tkt, &buf, &buflen);
  if (res == SHISHI_OK)
    {
      fprintf (fh, "%s:\n", buf);
      free (buf);
    }
  else
    fprintf (fh, "<unknown>:\n");

  t = shishi_tkt_authctime (tkt);
  fprintf (fh, _("Authtime:\t%s"), ctime (&t));

  t = shishi_tkt_startctime (tkt);
  if (t != (time_t) - 1)
    {
      p = ctime (&t);
      p[strlen (p) - 1] = '\0';
      fprintf (fh, _("Starttime:\t%s"), p);
      if (t > now)
	fprintf (fh, " NOT YET VALID");
      fprintf (fh, "\n");
    }

  t = shishi_tkt_endctime (tkt);
  if (t != (time_t) - 1)
    {
      p = ctime (&t);
      p[strlen (p) - 1] = '\0';
      fprintf (fh, _("Endtime:\t%s"), p);
      if (t < now)
	fprintf (fh, " EXPIRED");
      fprintf (fh, "\n");
    }

  t = shishi_tkt_renew_tillc (tkt);
  if (t != (time_t) - 1)
    fprintf (fh, _("Renewable till:\t%s"), ctime (&t));

  res = shishi_tkt_server (tkt, &buf, NULL);
  if (res == SHISHI_OK)
    {
      res = shishi_ticket_get_enc_part_etype (tkt->handle, tkt->ticket,
					      &keytype);
      if (res == SHISHI_OK)
	fprintf (fh, _("Server:\t\t%s key %s (%d)\n"), buf,
		 shishi_cipher_name (keytype), keytype);
      free (buf);
    }

  res = shishi_tkt_keytype (tkt, &keytype);
  if (res == SHISHI_OK)
    res = shishi_kdcrep_get_enc_part_etype (tkt->handle, tkt->kdcrep, &etype);
  if (res == SHISHI_OK)
    fprintf (fh, _("Ticket key:\t%s (%d) protected by %s (%d)\n"),
	     shishi_cipher_name (keytype), keytype,
	     shishi_cipher_name (etype), etype);

  res = shishi_tkt_flags (tkt, &flags);
  if (res == SHISHI_OK && flags)
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
