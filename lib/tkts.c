/* tkts.c --- Ticket set handling.
 * Copyright (C) 2002, 2003, 2004, 2006, 2007, 2008  Simon Josefsson
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
#include <minmax.h>

struct Shishi_tkts
{
  Shishi *handle;
  Shishi_tkt **tkts;
  int ntkts;
};

#define TICKET_FILE "tickets"

/**
 * shishi_tkts_default_file_guess:
 * @handle: Shishi library handle create by shishi_init().
 *
 * Guesses the default ticket filename; it is $SHISHI_TICKETS,
 * $SHISHI_HOME/tickets, or $HOME/.shishi/tickets.
 *
 * Return value: Returns default tkts filename as a string that
 * has to be deallocated with free() by the caller.
 **/
char *
shishi_tkts_default_file_guess (Shishi * handle)
{
  char *envfile;

  envfile = getenv ("SHISHI_TICKETS");
  if (envfile)
    return xstrdup (envfile);

  return shishi_cfg_userdirectory_file (handle, TICKET_FILE);
}

/**
 * shishi_tkts_default_file:
 * @handle: Shishi library handle create by shishi_init().
 *
 * Get filename of default ticket set.
 *
 * Return value: Returns the default ticket set filename used in the
 * library.  The string is not a copy, so don't modify or deallocate
 * it.
 **/
const char *
shishi_tkts_default_file (Shishi * handle)
{
  if (!handle->tktsdefaultfile)
    {
      char *p;

      p = shishi_tkts_default_file_guess (handle);
      shishi_tkts_default_file_set (handle, p);
      free (p);
    }

  return handle->tktsdefaultfile;
}

/**
 * shishi_tkts_default_file_set:
 * @handle: Shishi library handle create by shishi_init().
 * @tktsfile: string with new default tkts file name, or
 *                 NULL to reset to default.
 *
 * Set the default ticket set filename used in the library.  The
 * string is copied into the library, so you can dispose of the
 * variable immediately after calling this function.
 **/
void
shishi_tkts_default_file_set (Shishi * handle, const char *tktsfile)
{
  if (handle->tktsdefaultfile)
    free (handle->tktsdefaultfile);
  if (tktsfile)
    handle->tktsdefaultfile = xstrdup (tktsfile);
  else
    handle->tktsdefaultfile = NULL;
}

/**
 * shishi_tkts_default:
 * @handle: Shishi library handle create by shishi_init().
 *
 * Get the default ticket set for library handle.
 *
 * Return value: Return the handle global ticket set.
 **/
Shishi_tkts *
shishi_tkts_default (Shishi * handle)
{
  if (handle->tkts == NULL &&
      (shishi_tkts (handle, &handle->tkts) != SHISHI_OK))
    handle->tkts = NULL;

  return handle->tkts;
}

int
shishi_tkts_default_to_file (Shishi_tkts * tkts)
{
  return shishi_tkts_to_file (tkts, shishi_tkts_default_file (tkts->handle));
}

/**
 * shishi_tkts:
 * @handle: shishi handle as allocated by shishi_init().
 * @tkts: output pointer to newly allocated tkts handle.
 *
 * Get a new ticket set handle.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_tkts (Shishi * handle, Shishi_tkts ** tkts)
{
  *tkts = xcalloc (1, sizeof (**tkts));

  (*tkts)->handle = handle;

  return SHISHI_OK;
}

/**
 * shishi_tkts_done:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 *
 * Deallocates all resources associated with ticket set.  The ticket
 * set handle must not be used in calls to other shishi_tkts_*()
 * functions after this.
 **/
void
shishi_tkts_done (Shishi_tkts ** tkts)
{
  if (!tkts || !*tkts)
    return;

  if ((*tkts)->tkts)
    free ((*tkts)->tkts);
  free (*tkts);

  *tkts = NULL;

  return;
}

/**
 * shishi_tkts_size:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 *
 * Get size of ticket set.
 *
 * Return value: Returns number of tickets stored in ticket set.
 **/
int
shishi_tkts_size (Shishi_tkts * tkts)
{
  return tkts ? tkts->ntkts : -1;
}

/**
 * shishi_tkts_nth:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @ticketno: integer indicating requested ticket in ticket set.
 *
 * Get the n:th ticket in ticket set.
 *
 * Return value: Returns a ticket handle to the ticketno:th ticket in
 *   the ticket set, or NULL if ticket set is invalid or ticketno is
 *   out of bounds.  The first ticket is ticketno 0, the second
 *   ticketno 1, and so on.
 **/
Shishi_tkt *
shishi_tkts_nth (Shishi_tkts * tkts, int ticketno)
{
  if (tkts == NULL || ticketno >= tkts->ntkts)
    return NULL;

  return tkts->tkts[ticketno];
}

/**
 * shishi_tkts_remove:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @ticketno: ticket number of ticket in the set to remove.  The first
 *   ticket is ticket number 0.
 *
 * Remove a ticket, indexed by @ticketno, in ticket set.
 *
 * Return value: Returns SHISHI_OK if succesful or if ticketno larger
 *   than size of ticket set.
 **/
int
shishi_tkts_remove (Shishi_tkts * tkts, int ticketno)
{
  if (!tkts)
    return SHISHI_INVALID_TKTS;

  if (ticketno >= tkts->ntkts)
    return SHISHI_OK;

  if (ticketno < tkts->ntkts)
    memmove (&tkts->tkts[ticketno], &tkts->tkts[ticketno + 1],
	     sizeof (*tkts->tkts) * (tkts->ntkts - ticketno - 1));

  --tkts->ntkts;

  if (tkts->ntkts > 0)
    {
      tkts->tkts = xrealloc (tkts->tkts, sizeof (*tkts->tkts) * tkts->ntkts);
    }
  else
    {
      if (tkts->tkts)
	free (tkts->tkts);
      tkts->tkts = NULL;
    }

  return SHISHI_OK;
}

/**
 * shishi_tkts_add:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @tkt: ticket to be added to ticket set.
 *
 * Add a ticket to the ticket set.  Only the pointer is stored, so if
 * you modify @tkt, the ticket in the ticket set will also be
 * modified.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_tkts_add (Shishi_tkts * tkts, Shishi_tkt * tkt)
{
  if (!tkt)
    return SHISHI_INVALID_TICKET;

  if (tkts->ntkts++ == 0)
    tkts->tkts = xmalloc (sizeof (*tkts->tkts));
  else
    tkts->tkts = xrealloc (tkts->tkts, sizeof (*tkts->tkts) * tkts->ntkts);

  tkts->tkts[tkts->ntkts - 1] = tkt;

  return SHISHI_OK;
}

/**
 * shishi_tkts_new:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @ticket: input ticket variable.
 * @enckdcreppart: input ticket detail variable.
 * @kdcrep: input KDC-REP variable.
 *
 * Allocate a new ticket and add it to the ticket set.
 *
 * Note that @ticket, @enckdcreppart and @kdcrep are stored by
 * reference, so you must not de-allocate them before the ticket is
 * removed from the ticket set and de-allocated.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_tkts_new (Shishi_tkts * tkts,
		 Shishi_asn1 ticket, Shishi_asn1 enckdcreppart,
		 Shishi_asn1 kdcrep)
{
  Shishi_tkt *tkt;
  int res;

  /* XXX Who will de-allocate these? */
  tkt = shishi_tkt2 (tkts->handle, ticket, enckdcreppart, kdcrep);

  res = shishi_tkts_add (tkts, tkt);
  if (res != SHISHI_OK)
    {
      free (tkt);
      return res;
    }

  return SHISHI_OK;
}

/**
 * shishi_tkts_read:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @fh: file descriptor to read from.
 *
 * Read tickets from file descriptor and add them to the ticket set.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_tkts_read (Shishi_tkts * tkts, FILE * fh)
{
  int res;

  res = SHISHI_OK;
  while (!feof (fh))
    {
      Shishi_asn1 ticket;
      Shishi_asn1 enckdcreppart;
      Shishi_asn1 kdcrep;

      res = shishi_kdcrep_parse (tkts->handle, fh, &kdcrep);
      if (res != SHISHI_OK)
	{
	  res = SHISHI_OK;
	  break;
	}

      res = shishi_enckdcreppart_parse (tkts->handle, fh, &enckdcreppart);
      if (res != SHISHI_OK)
	break;

      res = shishi_ticket_parse (tkts->handle, fh, &ticket);
      if (res != SHISHI_OK)
	break;

      /* XXX Who will de-allocate these? */
      res = shishi_tkts_new (tkts, ticket, enckdcreppart, kdcrep);
      if (res != SHISHI_OK)
	break;

      if (VERBOSEASN1 (tkts->handle))
	{
	  printf ("Read ticket for principal `':\n");
	  shishi_kdcrep_print (tkts->handle, stdout, kdcrep);
	  shishi_enckdcreppart_print (tkts->handle, stdout, enckdcreppart);
	  shishi_ticket_print (tkts->handle, stdout, ticket);
	}
    }

  return res;
}

/**
 * shishi_tkts_from_file:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @filename: filename to read tickets from.
 *
 * Read tickets from file and add them to the ticket set.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_tkts_from_file (Shishi_tkts * tkts, const char *filename)
{
  FILE *fh;
  int res;

  fh = fopen (filename, "r");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  res = shishi_tkts_read (tkts, fh);
  if (res != SHISHI_OK)
    {
      fclose (fh);
      return res;
    }

  res = fclose (fh);
  if (res != 0)
    return SHISHI_IO_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_tkts_write:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @fh: file descriptor to write tickets to.
 *
 * Write tickets in set to file descriptor.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_tkts_write (Shishi_tkts * tkts, FILE * fh)
{
  int res;
  int i;

  if (!tkts)
    return SHISHI_INVALID_TKTS;

  for (i = 0; i < tkts->ntkts; i++)
    {
      res = shishi_kdcrep_print
	(tkts->handle, fh, shishi_tkt_kdcrep (tkts->tkts[i]));
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (tkts->handle,
			       "Could not print ticket: %s",
			       shishi_error (tkts->handle));
	  return res;
	}

      res = shishi_enckdcreppart_print
	(tkts->handle, fh, shishi_tkt_enckdcreppart (tkts->tkts[i]));
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (tkts->handle,
			       "Could not print ticket: %s",
			       shishi_error (tkts->handle));
	  return res;
	}

      res = shishi_ticket_print (tkts->handle, fh,
				 shishi_tkt_ticket (tkts->tkts[i]));
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (tkts->handle,
			       "Could not print ticket: %s",
			       shishi_error (tkts->handle));
	  return res;
	}

      fprintf (fh, "\n\n");
    }

  return SHISHI_OK;
}

/**
 * shishi_tkts_expire:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 *
 * Remove expired tickets from ticket set.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_tkts_expire (Shishi_tkts * tkts)
{
  int warn = 0;
  int i = 0;

  if (!tkts)
    return SHISHI_INVALID_TKTS;

  while (i < tkts->ntkts)
    {
      if (shishi_tkt_expired_p (tkts->tkts[i]))
	{
	  warn++;
	  shishi_tkts_remove (tkts, i);
	}
      else
	i++;
    }

  if (VERBOSE (tkts->handle) && warn)
    shishi_warn (tkts->handle,
		 ngettext ("removed %d expired ticket\n",
			   "removed %d expired tickets\n", warn), warn);

  return SHISHI_OK;
}

/**
 * shishi_tkts_to_file:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @filename: filename to write tickets to.
 *
 * Write tickets in set to file.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_tkts_to_file (Shishi_tkts * tkts, const char *filename)
{
  FILE *fh;
  int res;

  fh = fopen (filename, "w");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  res = shishi_tkts_write (tkts, fh);
  if (res != SHISHI_OK)
    {
      fclose (fh);
      return res;
    }

  res = fclose (fh);
  if (res != 0)
    return SHISHI_IO_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_tkts_print_for_service:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @fh: file descriptor to print to.
 * @service: service to limit tickets printed to, or NULL.
 *
 * Print description of tickets for specified service to file
 * descriptor.  If service is NULL, all tickets are printed.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_tkts_print_for_service (Shishi_tkts * tkts, FILE * fh,
			       const char *service)
{
  int res;
  int found;
  int i;

  found = 0;
  for (i = 0; i < shishi_tkts_size (tkts); i++)
    {
      Shishi_tkt *tkt = shishi_tkts_nth (tkts, i);

      if (service)
	{
	  char *buf;

	  res = shishi_tkt_server (tkt, &buf, NULL);
	  if (res != SHISHI_OK)
	    continue;

	  if (strcmp (service, buf) != 0)
	    {
	      free (buf);
	      continue;
	    }

	  free (buf);
	}

      printf ("\n");
      shishi_tkt_pretty_print (shishi_tkts_nth (tkts, i), fh);
      found++;
    }

  if (found)
    {
      printf (ngettext ("\n%d ticket found.\n", "\n%d tickets found.\n",
			found), found);
    }
  else
    {
      if (service)
	printf ("\nNo matching tickets found.\n");
      else
	printf ("\nNo tickets found.\n");
    }

  return SHISHI_OK;
}

/**
 * shishi_tkts_print:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @fh: file descriptor to print to.
 *
 * Print description of all tickets to file descriptor.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_tkts_print (Shishi_tkts * tkts, FILE * fh)
{
  return shishi_tkts_print_for_service (tkts, fh, NULL);
}

/**
 * shishi_tkt_match_p:
 * @tkt: ticket to test hints on.
 * @hint: structure with characteristics of ticket to be found.
 *
 * Test if a ticket matches specified hints.
 *
 * Return value: Returns 0 iff ticket fails to match given criteria.
 **/
int
shishi_tkt_match_p (Shishi_tkt * tkt, Shishi_tkts_hint * hint)
{
  if (hint->server && !shishi_tkt_server_p (tkt, hint->server))
    return 0;

  if (hint->client && !shishi_tkt_client_p (tkt, hint->client))
    return 0;

  if (!(hint->flags & SHISHI_TKTSHINTFLAGS_ACCEPT_EXPIRED) &&
      !shishi_tkt_valid_now_p (tkt))
    return 0;

  if ((hint->tktflags & SHISHI_TICKETFLAGS_FORWARDABLE) &&
      !shishi_tkt_forwardable_p (tkt))
    return 0;

  if ((hint->tktflags & SHISHI_TICKETFLAGS_FORWARDED) &&
      !shishi_tkt_forwarded_p (tkt))
    return 0;

  if ((hint->tktflags & SHISHI_TICKETFLAGS_RENEWABLE) &&
      !shishi_tkt_renewable_p (tkt))
    return 0;

  if ((hint->tktflags & SHISHI_TICKETFLAGS_PROXIABLE) &&
      !shishi_tkt_proxiable_p (tkt))
    return 0;

  if ((hint->tktflags & SHISHI_TICKETFLAGS_PROXY) &&
      !shishi_tkt_proxy_p (tkt))
    return 0;

  if (hint->etype && !shishi_tkt_keytype_p (tkt, hint->etype))
    return 0;

  return 1;
}

/**
 * shishi_tkts_find:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @hint: structure with characteristics of ticket to be found.
 *
 * Search the ticketset sequentially (from ticket number 0 through all
 * tickets in the set) for a ticket that fits the given
 * characteristics.  If a ticket is found, the hint->startpos field is
 * updated to point to the next ticket in the set, so this function
 * can be called repeatedly with the same hint argument in order to
 * find all tickets matching a certain criterium.  Note that if
 * tickets are added to, or removed from, the ticketset during a query
 * with the same hint argument, the hint->startpos field must be
 * updated appropriately.
 *
 * Here is how you would typically use this function:
 *
 *   Shishi_tkts_hint  hint;
 *
 *   Shishi_tkt  tkt;
 *
 *
 *   memset(&hint, 0, sizeof(hint));
 *
 *   hint.server = "imap/mail.example.org";
 *
 *   tkt = shishi_tkts_find (shishi_tkts_default(handle), &hint);
 *
 *   if (!tkt)
 *
 *     printf("No ticket found...\n");
 *
 *   else
 *
 *     do_something_with_ticket (tkt);
 *
 * Return value: Returns a ticket if found, or NULL if no further
 *               matching tickets could be found.
 **/
Shishi_tkt *
shishi_tkts_find (Shishi_tkts * tkts, Shishi_tkts_hint * hint)
{
  int i;

  if (!tkts)
    return NULL;

  if (VERBOSENOISE (tkts->handle))
    {
      fprintf (stderr, "Searching tickets... ");
      if (hint->server)
	fprintf (stderr, "server=`%s' ", hint->server);
      if (hint->client)
	fprintf (stderr, "client=`%s' ", hint->client);
      fprintf (stderr, "\n");
    }

  for (i = hint->startpos; i < tkts->ntkts; i++)
    {
      if (!shishi_tkt_match_p (tkts->tkts[i], hint))
	continue;

      hint->startpos = i + 1;
      return tkts->tkts[i];
    }

  hint->startpos = i;
  return NULL;
}

/**
 * shishi_tkts_find_for_clientserver:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @client: client name to find ticket for.
 * @server: server name to find ticket for.
 *
 * Short-hand function for searching the ticket set for a ticket for
 * the given client and server.  See shishi_tkts_find().
 *
 * Return value: Returns a ticket if found, or NULL.
 **/
Shishi_tkt *
shishi_tkts_find_for_clientserver (Shishi_tkts * tkts,
				   const char *client, const char *server)
{
  Shishi_tkts_hint hint;
  Shishi_tkt *tkt;

  memset (&hint, 0, sizeof (hint));
  hint.server = (char *) server;
  hint.client = (char *) client;

  tkt = shishi_tkts_find (tkts, &hint);

  return tkt;
}

/**
 * shishi_tkts_find_for_server:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @server: server name to find ticket for.
 *
 * Short-hand function for searching the ticket set for a ticket for
 * the given server using the default client principal.  See
 * shishi_tkts_find_for_clientserver() and shishi_tkts_find().
 *
 * Return value: Returns a ticket if found, or NULL.
 **/
Shishi_tkt *
shishi_tkts_find_for_server (Shishi_tkts * tkts, const char *server)
{
  return shishi_tkts_find_for_clientserver
    (tkts, shishi_principal_default (tkts->handle), server);
}

/* Set flags and times in KDC-REQ based on hint. */
static int
act_hint_on_kdcreq (Shishi * handle,
		    Shishi_tkts_hint * hint, Shishi_asn1 kdcreq)
{
  time_t starttime = hint->starttime ? hint->starttime : time (NULL);
  time_t endtime = hint->endtime ? hint->endtime :
    starttime + handle->ticketlife;
  time_t renew_till = hint->renew_till ? hint->renew_till :
    starttime + handle->renewlife;
  int rc;

  if (hint->starttime)
    {
      rc = shishi_asn1_write (handle, kdcreq, "req-body.from",
			      shishi_generalize_time (handle, starttime), 0);
      if (rc != SHISHI_OK)
	{
	  shishi_error_printf (handle, "Cannot set starttime: %s",
			       shishi_strerror (rc));
	  return rc;
	}
    }

  if (hint->endtime)
    {
      rc = shishi_asn1_write (handle, kdcreq, "req-body.till",
			      shishi_generalize_time (handle, endtime), 0);
      if (rc != SHISHI_OK)
	{
	  shishi_error_printf (handle, "Cannot set endtime: %s",
			       shishi_strerror (rc));
	  return rc;
	}
    }

  if (hint->tktflags & SHISHI_TICKETFLAGS_FORWARDABLE)
    {
      rc = shishi_kdcreq_options_add (handle, kdcreq,
				      SHISHI_KDCOPTIONS_FORWARDABLE);
      if (rc != SHISHI_OK)
	goto done;
    }

  if (hint->tktflags & SHISHI_TICKETFLAGS_FORWARDED)
    {
      rc = shishi_kdcreq_options_add (handle, kdcreq,
				      SHISHI_KDCOPTIONS_FORWARDED);
      if (rc != SHISHI_OK)
	goto done;
    }

  if (hint->tktflags & SHISHI_TICKETFLAGS_RENEWABLE)
    {
      rc = shishi_kdcreq_options_add (handle, kdcreq,
				      SHISHI_KDCOPTIONS_RENEWABLE);
      if (rc != SHISHI_OK)
	goto done;

      rc = shishi_asn1_write (handle, kdcreq, "req-body.rtime",
			      shishi_generalize_time (handle, renew_till), 0);
      if (rc != SHISHI_OK)
	{
	  shishi_error_printf (handle, "Cannot set renewtill: %s",
			       shishi_strerror (rc));
	  return rc;
	}
    }

  if (hint->tktflags & SHISHI_TICKETFLAGS_PROXIABLE)
    {
      rc = shishi_kdcreq_options_add (handle, kdcreq,
				      SHISHI_KDCOPTIONS_PROXIABLE);
      if (rc != SHISHI_OK)
	goto done;
    }

  if (hint->tktflags & SHISHI_TICKETFLAGS_PROXY)
    {
      rc = shishi_kdcreq_options_add (handle, kdcreq,
				      SHISHI_KDCOPTIONS_PROXY);
      if (rc != SHISHI_OK)
	goto done;
    }


  if (hint->etype)
    {
      rc = shishi_kdcreq_set_etype (handle, kdcreq, &hint->etype, 1);
      if (rc != SHISHI_OK)
	goto done;
    }

  return SHISHI_OK;

done:
  shishi_error_printf (handle, "Cannot set KDC Options: %s",
		       shishi_strerror (rc));
  return rc;
}

/* Make sure the ticket granting ticket is suitable for the wanted
   ticket.  E.g., if the wanted ticket should be a PROXY ticket, the
   ticket granting ticket must be a PROXIABLE ticket for things to
   work. */
static void
set_tgtflags_based_on_hint (Shishi_tkts_hint * tkthint,
			    Shishi_tkts_hint * tgthint)
{
  if (tkthint->tktflags & SHISHI_TICKETFLAGS_FORWARDABLE)
    tgthint->tktflags |= SHISHI_TICKETFLAGS_FORWARDABLE;

  if (tkthint->tktflags & SHISHI_TICKETFLAGS_FORWARDED)
    tgthint->tktflags |= SHISHI_TICKETFLAGS_FORWARDABLE;

  if (tkthint->tktflags & SHISHI_TICKETFLAGS_PROXIABLE)
    tgthint->tktflags |= SHISHI_TICKETFLAGS_PROXIABLE;

  if (tkthint->tktflags & SHISHI_TICKETFLAGS_PROXY)
    tgthint->tktflags |= SHISHI_TICKETFLAGS_PROXIABLE;

  if (tkthint->tktflags & SHISHI_TICKETFLAGS_RENEWABLE)
    tgthint->tktflags |= SHISHI_TICKETFLAGS_RENEWABLE;

  if (tkthint->kdcoptions & SHISHI_KDCOPTIONS_RENEW)
    tgthint->tktflags |= SHISHI_TICKETFLAGS_RENEWABLE;

  if (tkthint->endtime)
    tgthint->endtime = tkthint->endtime;

  if (tkthint->passwd)
    tgthint->passwd = tkthint->passwd;

  if (tkthint->preauthetype)
    tgthint->preauthetype = tkthint->preauthetype;

  if (tkthint->preauthsalt)
    {
      tgthint->preauthsalt = tkthint->preauthsalt;
      tgthint->preauthsaltlen = tkthint->preauthsaltlen;
    }

  if (tkthint->preauths2kparams)
    {
      tgthint->preauths2kparams = tkthint->preauths2kparams;
      tgthint->preauths2kparamslen = tkthint->preauths2kparamslen;
    }
}

/* Pre-authenticate request, based on LOCHINT.  Currently only
   PA-ENC-TIMESTAMP is supported.  */
static int
do_preauth (Shishi_tkts *tkts, Shishi_tkts_hint *lochint, Shishi_as *as)
{
  int rc = SHISHI_OK;

  if (lochint->preauthetype)
    {
      Shishi_key *key;
      char *user;

      /* XXX Don't prompt for password here? */

      rc = shishi_asreq_clientrealm (tkts->handle, shishi_as_req (as),
				     &user, NULL);
      if (rc != SHISHI_OK)
	return rc;

      if (lochint->passwd == NULL)
	{
	  rc = shishi_prompt_password (tkts->handle, &lochint->passwd,
				       "Enter password for `%s': ", user);
	  if (rc != SHISHI_OK)
	    return rc;
	}

      if (!lochint->preauthsalt)
	{
	  rc = shishi_derive_default_salt (tkts->handle, user,
					   &lochint->preauthsalt);
	  if (rc != SHISHI_OK)
	    return rc;

	  lochint->preauthsaltlen = strlen (lochint->preauthsalt);
	}

      rc = shishi_key_from_string (tkts->handle, lochint->preauthetype,
				   lochint->passwd, strlen (lochint->passwd),
				   lochint->preauthsalt,
				   lochint->preauthsaltlen,
				   lochint->preauths2kparams, &key);
      if (rc != SHISHI_OK)
	return rc;

      rc = shishi_kdcreq_add_padata_preauth (tkts->handle,
					     shishi_as_req (as), key);
    }

  return rc;
}

/* Handle ETYPE-INFO and ETYPE-INFO2 pre-auth data. */
static int
recover_preauth_info (Shishi_tkts *tkts,
		      Shishi_as *as,
		      Shishi_tkts_hint *lochint,
		      Shishi_asn1 einfos,
		      bool isinfo2,
		      bool *retry)
{
  size_t foundpos = SIZE_MAX;
  size_t i, n;
  int rc;

  shishi_verbose (tkts->handle, "Found INFO-ETYPE(2) pre-auth hints");

  if (VERBOSEASN1(tkts->handle))
    {
      if (isinfo2)
	shishi_etype_info2_print (tkts->handle, stdout, einfos);
      else
	shishi_etype_info_print (tkts->handle, stdout, einfos);
    }

  if (lochint->preauthetype)
    {
      shishi_verbose (tkts->handle, "Pre-auth data already specified");
      return SHISHI_OK;
    }

  rc = shishi_asn1_number_of_elements (tkts->handle, einfos, "", &n);
  if (rc != SHISHI_OK)
    return rc;

  for (i = 1; i <= n; i++)
    {
      char *format;
      int32_t etype;

      format = xasprintf ("?%d.etype", i);
      rc = shishi_asn1_read_int32 (tkts->handle, einfos, format, &etype);
      free (format);
      if (rc == SHISHI_OK)
	{
	  size_t j;

	  shishi_verbose (tkts->handle, "Server has etype %d", etype);

	  for (j = 0; j < tkts->handle->nclientkdcetypes; j++)
	    {
	      if (etype == tkts->handle->clientkdcetypes[j])
		{
		  if (j < foundpos && VERBOSENOISE(tkts->handle))
		    {
		      shishi_verbose (tkts->handle, "New best etype %d", etype);

		      /* XXX mem leak. */

		      format = xasprintf ("?%d.salt", i);
		      rc = shishi_asn1_read (tkts->handle, einfos, format,
					     &lochint->preauthsalt,
					     &lochint->preauthsaltlen);
		      free (format);
		      if (rc != SHISHI_OK && rc != SHISHI_ASN1_NO_ELEMENT)
			return rc;

		      if (isinfo2)
			{
			  format = xasprintf ("?%d.s2kparams", i);
			  rc = shishi_asn1_read (tkts->handle, einfos, format,
						 &lochint->preauths2kparams,
						 &lochint->preauths2kparamslen);
			  free (format);
			  if (rc != SHISHI_OK && rc != SHISHI_ASN1_NO_ELEMENT)
			    return rc;
			}
		    }

		  foundpos = MIN(foundpos, j);
		}
	    }
	}
    }

  if (foundpos != SIZE_MAX)
    {
      lochint->preauthetype = tkts->handle->clientkdcetypes[foundpos];

      shishi_verbose (tkts->handle, "Best pre-auth etype was %d",
		      lochint->preauthetype);

      *retry = true;
    }

  return SHISHI_OK;
}

/* Called when KDC refused with a NEED_PREAUTH error.  This function
   should look at the METHOD-DATA, figure out what kind of pre-auth is
   requested, and if it is able to figure out how to recover from the
   error, set *RETRY to true and set any hints in LOCHINT that help
   do_preauth() compute the proper pre-auth data.  */
static int
recover_preauth (Shishi_tkts *tkts,
		 Shishi_as *as,
		 Shishi_tkts_hint *lochint,
		 bool *retry)
{
  Shishi_asn1 krberror = shishi_as_krberror (as);
  Shishi_asn1 pas;
  size_t i, n;
  int rc;

  *retry = false;

  shishi_verbose (tkts->handle, "Server requests pre-auth data");

  rc = shishi_krberror_methoddata (tkts->handle, krberror, &pas);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_asn1_number_of_elements (tkts->handle, pas, "", &n);
  if (rc == SHISHI_OK)
    {
      for (i = 1; i <= n; i++)
	{
	  char *format = xasprintf ("?%d.padata-type", i);
	  int32_t padatatype;

	  rc = shishi_asn1_read_int32 (tkts->handle, pas, format,
					&padatatype);
	  free (format);
	  if (rc == SHISHI_OK)
	    {
	      shishi_verbose (tkts->handle, "Looking at pa-type %d",
			      padatatype);

	      switch (padatatype)
		{
		  /* XXX Don't parse INFO structures if there is a
		     INFO2. */

		case SHISHI_PA_ETYPE_INFO:
		case SHISHI_PA_ETYPE_INFO2:
		  {
		    char *der;
		    size_t len;
		    Shishi_asn1 einfos;

		    format = xasprintf ("?%d.padata-value", i);
		    rc = shishi_asn1_read (tkts->handle, pas, format,
					   &der, &len);
		    free (format);
		    if (rc != SHISHI_OK)
		      {
			shishi_error_printf (tkts->handle,
					     "Can't extract PA-DATA value");
			continue;
		      }

		    if (padatatype == SHISHI_PA_ETYPE_INFO)
		      einfos = shishi_der2asn1_etype_info (tkts->handle,
							   der, len);
		    else
		      einfos = shishi_der2asn1_etype_info2 (tkts->handle,
							    der, len);
		    free (der);
		    if (!einfos)
		      {
			shishi_error_printf (tkts->handle,
					     "Can't DER decode PA-DATA");
			continue;
		      }

		    rc = recover_preauth_info
		      (tkts, as, lochint, einfos,
		       padatatype == SHISHI_PA_ETYPE_INFO2, retry);
		    if (rc != SHISHI_OK)
		      {
			shishi_error_printf (tkts->handle,
					     "Could not use pre-auth data: %s",
					     shishi_strerror (rc));
			continue;
		      }

		    shishi_asn1_done (tkts->handle, einfos);
		  }
		  break;

		default:
		  break;
		}
	    }
	}
    }

  shishi_asn1_done (tkts->handle, pas);

  return SHISHI_OK;
}

/**
 * shishi_tkts_get_tgt:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @hint: structure with characteristics of ticket to begot.
 *
 * Get a ticket granting ticket (TGT) suitable for acquiring ticket
 * matching the hint.  I.e., get a TGT for the server realm in the
 * hint structure (hint->serverrealm), or the default realm if the
 * serverrealm field is NULL.  Can result in AS exchange.
 *
 * Currently this function do not implement cross realm logic.
 *
 * This function is used by shishi_tkts_get(), which is probably what
 * you really want to use unless you have special needs.
 *
 * Return value: Returns a ticket granting ticket if successful, or
 *   NULL if this function is unable to acquire on.
 **/
Shishi_tkt *
shishi_tkts_get_tgt (Shishi_tkts * tkts, Shishi_tkts_hint * hint)
{
  Shishi_tkts_hint lochint;
  Shishi_as *as;
  Shishi_tkt *tgt;
  int rc;

  /* XXX cross-realm operation */

  memset (&lochint, 0, sizeof (lochint));
  asprintf (&lochint.server, "krbtgt/%s", hint->serverrealm ?
	    hint->serverrealm : shishi_realm_default (tkts->handle));
  set_tgtflags_based_on_hint (hint, &lochint);

  tgt = shishi_tkts_find (tkts, &lochint);

  free (lochint.server);
  lochint.server = NULL;

  if (tgt)
    return tgt;

  if (hint->flags & SHISHI_TKTSHINTFLAGS_NON_INTERACTIVE)
    return NULL;

 again:
  rc = shishi_as (tkts->handle, &as);
  if (rc == SHISHI_OK)
    rc = act_hint_on_kdcreq (tkts->handle, &lochint, shishi_as_req (as));
  if (rc == SHISHI_OK)
    rc = do_preauth (tkts, &lochint, as);
  if (rc == SHISHI_OK)
    rc = shishi_as_req_build (as);
  if (rc == SHISHI_OK)
    rc = shishi_as_sendrecv_hint (as, &lochint);
  if (rc == SHISHI_OK)
    rc = shishi_as_rep_process (as, NULL, lochint.passwd);
  if (rc == SHISHI_GOT_KRBERROR
      && shishi_krberror_errorcode_fast (tkts->handle,
					 shishi_as_krberror (as))
      == SHISHI_KDC_ERR_PREAUTH_REQUIRED)
    {
      bool retry = false;

      rc = recover_preauth (tkts, as, &lochint, &retry);
      if (rc != SHISHI_OK)
	return NULL;

      if (retry)
	{
	  shishi_as_done (as);
	  goto again;
	}

      shishi_error_printf (tkts->handle, "Unsupported pre-auth required");
      return NULL;
    }
  if (rc != SHISHI_OK)
    {
      shishi_error_printf (tkts->handle,
			   "AS exchange failed: %s\n%s\n",
			   shishi_strerror (rc), shishi_error (tkts->handle));
      return NULL;
    }

  /* XXX free lochint members */

  tgt = shishi_as_tkt (as);
  if (!tgt)
    {
      shishi_error_printf (tkts->handle, "No ticket in AS-REP");
      return NULL;
    }

  if (VERBOSENOISE (tkts->handle))
    {
      printf ("Received ticket granting ticket:\n");
      shishi_tkt_pretty_print (tgt, stdout);
    }

  rc = shishi_tkts_add (tkts, tgt);
  if (rc != SHISHI_OK)
    printf ("Could not add ticket: %s", shishi_strerror (rc));

  return tgt;
}

/**
 * shishi_tkts_get_tgs:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @hint: structure with characteristics of ticket to begot.
 * @tgt: ticket granting ticket to use.
 *
 * Get a ticket via TGS exchange using specified ticket granting
 * ticket.
 *
 * This function is used by shishi_tkts_get(), which is probably what
 * you really want to use unless you have special needs.
 *
 * Return value: Returns a ticket if successful, or NULL if this
 *   function is unable to acquire on.
 **/
Shishi_tkt *
shishi_tkts_get_tgs (Shishi_tkts * tkts,
		     Shishi_tkts_hint * hint, Shishi_tkt * tgt)
{
  Shishi_tgs *tgs;
  Shishi_tkt *tkt;
  int rc;

  rc = shishi_tgs (tkts->handle, &tgs);
  shishi_tgs_tgtkt_set (tgs, tgt);
  if (rc == SHISHI_OK)
    rc = act_hint_on_kdcreq (tkts->handle, hint, shishi_tgs_req (tgs));
  if (rc == SHISHI_OK)
    rc = shishi_tgs_set_server (tgs, hint->server);
  if (rc == SHISHI_OK)
    rc = shishi_tgs_req_build (tgs);
  if (rc == SHISHI_OK)
    rc = shishi_tgs_sendrecv_hint (tgs, hint);
  if (rc == SHISHI_OK)
    rc = shishi_tgs_rep_process (tgs);
  if (rc != SHISHI_OK)
    {
      shishi_error_printf (tkts->handle,
			   "TGS exchange failed: %s\n%s\n",
			   shishi_strerror (rc), shishi_error (tkts->handle));
      if (rc == SHISHI_GOT_KRBERROR)
	shishi_krberror_pretty_print (tkts->handle, stdout,
				      shishi_tgs_krberror (tgs));
      return NULL;
    }

  tkt = shishi_tgs_tkt (tgs);
  if (!tkt)
    {
      shishi_error_printf (tkts->handle, "No ticket in TGS-REP?!: %s",
			   shishi_error (tkts->handle));
      return NULL;
    }

  if (VERBOSENOISE (tkts->handle))
    {
      printf ("Received ticket:\n");
      shishi_tkt_pretty_print (tkt, stdout);
    }

  rc = shishi_tkts_add (tkts, tkt);
  if (rc != SHISHI_OK)
    printf ("Could not add ticket: %s", shishi_strerror (rc));

  return tkt;
}

/**
 * shishi_tkts_get:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @hint: structure with characteristics of ticket to begot.
 *
 * Get a ticket matching given characteristics.  This function first
 * looks in the ticket set for the ticket, then tries to find a
 * suitable TGT, possibly via an AS exchange, using
 * shishi_tkts_get_tgt(), and then use that TGT in a TGS exchange to
 * get the ticket.
 *
 * Currently this function do not implement cross realm logic.
 *
 * Return value: Returns a ticket if found, or NULL if this function
 *               is unable to get the ticket.
 **/
Shishi_tkt *
shishi_tkts_get (Shishi_tkts * tkts, Shishi_tkts_hint * hint)
{
  Shishi_tkt *tkt, *tgt;

  /* If we already have a matching ticket, avoid getting a new one. */
  hint->startpos = 0;
  tkt = shishi_tkts_find (tkts, hint);
  if (tkt)
    return tkt;

  tgt = shishi_tkts_get_tgt (tkts, hint);
  if (!tgt)
    {
      shishi_error_printf (tkts->handle, "Could not get TGT for ticket.");
      return NULL;
    }

  if (shishi_tkt_match_p (tgt, hint))
    return tgt;

  tkt = shishi_tkts_get_tgs (tkts, hint, tgt);
  if (!tkt)
    {
      shishi_error_printf (tkts->handle, "Could not get ticket using TGT.");
      return NULL;
    }

  return tkt;
}

/**
 * shishi_tkts_get_for_clientserver:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @client: client name to get ticket for.
 * @server: server name to get ticket for.
 *
 * Short-hand function for getting a ticket for the given client and
 * server.  See shishi_tkts_get().
 *
 * Return value: Returns a ticket if found, or NULL.
 **/
Shishi_tkt *
shishi_tkts_get_for_clientserver (Shishi_tkts * tkts,
				  const char *client, const char *server)
{
  Shishi_tkts_hint hint;
  Shishi_tkt *tkt;

  memset (&hint, 0, sizeof (hint));
  hint.client = (char *) client;
  hint.server = (char *) server;

  tkt = shishi_tkts_get (tkts, &hint);

  return tkt;
}

/**
 * shishi_tkts_get_for_server:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @server: server name to get ticket for.
 *
 * Short-hand function for getting a ticket for the given server and
 * the default principal client.  See shishi_tkts_get().
 *
 * Return value: Returns a ticket if found, or NULL.
 **/
Shishi_tkt *
shishi_tkts_get_for_server (Shishi_tkts * tkts, const char *server)
{
  return shishi_tkts_get_for_clientserver
    (tkts, shishi_principal_default (tkts->handle), server);
}

Shishi_tkt *
shishi_tkts_get_for_localservicepasswd (Shishi_tkts * tkts,
					const char *service,
					const char *passwd)
{
  Shishi_tkt *tkt;
  Shishi_tkts_hint hint;

  memset (&hint, 0, sizeof (hint));
  hint.client = (char *) shishi_principal_default (tkts->handle);
  hint.server = shishi_server_for_local_service (tkts->handle, service);
  hint.passwd = (char *) passwd;

  tkt = shishi_tkts_get (tkts, &hint);

  free (hint.server);

  return tkt;
}
