/* ticketset.c	Ticket set handling.
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

/* XXX how to generalize shishi_ticketset_{get,find}_ticket_for_*()??
   unclean with lots of different functions... */

#include "internal.h"

struct Shishi_ticketset
{
  Shishi *handle;
  Shishi_ticket **tickets;
  int ntickets;
};

/**
 * shishi_ticketset_default_file_guess:
 *
 * Guesses the default ticket filename; it is $HOME/.shishi/tickets.
 *
 * Return value: Returns default ticketset filename as a string that
 * has to be deallocated with free() by the caller.
 **/
char *
shishi_ticketset_default_file_guess (void)
{
  char *home;
  char *p;

  home = getenv ("HOME");

  if (home == NULL)
    home = "";

  shishi_asprintf (&p, "%s%s", home, TICKET_FILE);

  return p;
}

/**
 * shishi_ticketset_default_file:
 * @handle: Shishi library handle create by shishi_init().
 *
 * Return value: Returns the default ticket set filename used in the
 * library.  (Not a copy of it, so don't modify or deallocate it.)
 **/
const char *
shishi_ticketset_default_file (Shishi * handle)
{
  if (!handle->ticketsetdefaultfile)
    {
      char *p;

      p=shishi_ticketset_default_file_guess ();
      shishi_ticketset_default_file_set (handle, p);
      free (p);
    }

  return handle->ticketsetdefaultfile;
}

/**
 * shishi_ticketset_default_file_set:
 * @handle: Shishi library handle create by shishi_init().
 * @ticketsetfile: string with new default ticketset file name, or
 *                 NULL to reset to default.
 *
 * Set the default ticket set filename used in the library.  The
 * string is copied into the library, so you can dispose of the
 * variable immediately after calling this function.
 **/
void
shishi_ticketset_default_file_set (Shishi * handle, const char *ticketsetfile)
{
  if (handle->ticketsetdefaultfile)
    free (handle->ticketsetdefaultfile);
  if (ticketsetfile)
    handle->ticketsetdefaultfile = strdup(ticketsetfile);
  else
    handle->ticketsetdefaultfile = NULL;
}

/**
 * shishi_ticketset:
 * @handle: shishi handle as allocated by shishi_init().
 * @ticketset: output pointer to newly allocated ticketset handle.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_ticketset (Shishi * handle, Shishi_ticketset ** ticketset)
{
  *ticketset = malloc (sizeof (**ticketset));
  if (*ticketset == NULL)
    return SHISHI_MALLOC_ERROR;
  memset(*ticketset, 0, sizeof(**ticketset));

  (*ticketset)->handle = handle;

  return SHISHI_OK;
}

/**
 * shishi_ticketset_size:
 * @ticketset: ticket set handle as allocated by shishi_ticketset().
 *
 * Return value: Returns number of tickets stored in ticket set.
 **/
int
shishi_ticketset_size (Shishi_ticketset * ticketset)
{
  return ticketset->ntickets;
}

/**
 * shishi_ticketset_get:
 * @ticketset: ticket set handle as allocated by shishi_ticketset().
 * @ticketno: integer indicating requested ticket in ticket set.
 *
 * Return value: Returns a ticket handle to the ticketno:th ticket in
 * the ticket set, or NULL if ticket set is invalid or ticketno is out
 * of bounds.  The first ticket is ticketno 0, the second ticketno 1,
 * and so on.
 **/
Shishi_ticket *
shishi_ticketset_get (Shishi_ticketset * ticketset, int ticketno)
{
  if (ticketset == NULL || ticketno >= ticketset->ntickets)
    return NULL;

  return ticketset->tickets[ticketno];
}

/**
 * shishi_ticketset_remove:
 * @ticketset: ticket set handle as allocated by shishi_ticketset().
 * @ticketnum: ticket number of ticket in the set to remove.  The
 * first ticket is ticket number 0.
 *
 * Return value: Returns SHISHI_OK if succesful or if ticketno
 * larger than size of ticket set.
 **/
int
shishi_ticketset_remove (Shishi_ticketset * ticketset,
			 int ticketno)
{
  if (!ticketset)
    return SHISHI_INVALID_TICKETSET;

  if (ticketno >= ticketset->ntickets)
    return SHISHI_OK;

  if (ticketno < ticketset->ntickets)
    memmove(&ticketset->tickets[ticketno], &ticketset->tickets[ticketno + 1],
	    sizeof(*ticketset->tickets) *
	    (ticketset->ntickets - ticketno - 1));

  --ticketset->ntickets;

  if (ticketset->ntickets > 0)
    {
      ticketset->tickets = realloc (ticketset->tickets,
				    sizeof (*ticketset->tickets) *
				    ticketset->ntickets);
      if (ticketset->tickets == NULL)
	return SHISHI_MALLOC_ERROR;
    }
  else
    {
      if (ticketset->tickets)
	free(ticketset->tickets);
      ticketset->tickets = NULL;
    }

  return SHISHI_OK;
}

/**
 * shishi_ticketset_add:
 * @ticketset: ticket set handle as allocated by shishi_ticketset().
 * @ticket: ticket to be added to ticket set.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_ticketset_add (Shishi_ticketset * ticketset, Shishi_ticket * ticket)
{
  if (!ticket)
    return SHISHI_INVALID_TICKET;

  if (ticketset->ntickets++ == 0)
    ticketset->tickets = malloc (sizeof (*ticketset->tickets));
  else
    ticketset->tickets = realloc (ticketset->tickets,
				  sizeof (*ticketset->tickets) *
				  ticketset->ntickets);
  if (ticketset->tickets == NULL)
    return SHISHI_MALLOC_ERROR;

  ticketset->tickets[ticketset->ntickets - 1] = ticket;

  return SHISHI_OK;
}

/**
 * shishi_ticketset_new:
 * @ticketset: ticket set handle as allocated by shishi_ticketset().
 * @ticket: input ticket variable.
 * @enckdcreppart: input ticket detail variable.
 * @kdcrep: input KDC-REP variable.
 *
 * Allocate a new ticket and add it to the ticket set.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_ticketset_new (Shishi_ticketset * ticketset,
		      ASN1_TYPE ticket,
		      ASN1_TYPE enckdcreppart,
		      ASN1_TYPE kdcrep)
{
  Shishi_ticket *tkt;
  int res;

  tkt = shishi_ticket (ticketset->handle, ticket, enckdcreppart, kdcrep);
  if (tkt == NULL)
    return SHISHI_MALLOC_ERROR;

  res = shishi_ticketset_add (ticketset, tkt);
  if (res != SHISHI_OK)
    {
      free (tkt);
      return res;
    }

  return SHISHI_OK;
}

/**
 * shishi_ticketset_read:
 * @ticketset: ticket set handle as allocated by shishi_ticketset().
 * @fh: file descriptor to read from.
 *
 * Read tickets from file descriptor and add them to the ticket set.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_ticketset_read (Shishi_ticketset * ticketset, FILE * fh)
{
  int res;

  res = SHISHI_OK;
  while (!feof (fh))
    {
      ASN1_TYPE ticket;
      ASN1_TYPE enckdcreppart;
      ASN1_TYPE kdcrep;

      res = shishi_kdcrep_parse (ticketset->handle, fh, &kdcrep);
      if (res != SHISHI_OK)
	{
	  res = SHISHI_OK;
	  break;
	}

      res = shishi_enckdcreppart_parse (ticketset->handle, fh, &enckdcreppart);
      if (res != SHISHI_OK)
	break;

      res = shishi_ticket_parse (ticketset->handle, fh, &ticket);
      if (res != SHISHI_OK)
	break;

      res = shishi_ticketset_new (ticketset, ticket, enckdcreppart, kdcrep);
      if (res != SHISHI_OK)
	break;

      if (VERBOSE (ticketset->handle))
	{
	  printf ("Read ticket for principal `':\n");
	  shishi_kdcrep_print (ticketset->handle, stdout, kdcrep);
	  shishi_enckdcreppart_print (ticketset->handle, stdout,
				      enckdcreppart);
	  shishi_asn1ticket_print (ticketset->handle, stdout, ticket);
	}
    }

  return res;
}

/**
 * shishi_ticketset_from_file:
 * @ticketset: ticket set handle as allocated by shishi_ticketset().
 * @filename: filename to read tickets from.
 *
 * Read tickets from file and add them to the ticket set.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_ticketset_from_file (Shishi_ticketset * ticketset,
			    const char *filename)
{
  FILE *fh;
  int res;

  fh = fopen (filename, "r");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  res = shishi_ticketset_read (ticketset, fh);
  if (res != SHISHI_OK)
    {
      fclose (fh);
      return res;
    }

  res = fclose (fh);
  if (res != 0)
    return SHISHI_FCLOSE_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_ticketset_write:
 * @ticketset: ticket set handle as allocated by shishi_ticketset().
 * @filename: filename to write tickets to.
 *
 * Write tickets in set to file descriptor.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_ticketset_write (Shishi_ticketset * ticketset, FILE * fh)
{
  int res;
  int i;

  for (i = 0; i < ticketset->ntickets; i++)
    {
      res = shishi_kdcrep_print
	(ticketset->handle, fh, shishi_ticket_kdcrep(ticketset->tickets[i]));
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (ticketset->handle,
			       "Could not print ticket: %s\n",
			       shishi_strerror_details (ticketset->handle));
	  return res;
	}

      res = shishi_enckdcreppart_print
	(ticketset->handle, fh,
	 shishi_ticket_enckdcreppart(ticketset->tickets[i]));
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (ticketset->handle,
			       "Could not print ticket: %s\n",
			       shishi_strerror_details (ticketset->handle));
	  return res;
	}

      res = shishi_asn1ticket_print
	(ticketset->handle, fh, shishi_ticket_ticket (ticketset->tickets[i]));
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (ticketset->handle,
			       "Could not print ticket: %s\n",
			       shishi_strerror_details (ticketset->handle));
	  return res;
	}

      fprintf (fh, "\n\n");
    }

  return SHISHI_OK;
}

/**
 * shishi_ticketset_expire:
 * @ticketset: ticket set handle as allocated by shishi_ticketset().
 *
 * Remove expired tickets from ticket set.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_ticketset_expire (Shishi_ticketset * ticketset)
{
  int warn = 0;
  int i = 0;

  while (i < ticketset->ntickets)
    {
      if (!shishi_ticket_valid_now_p (ticketset->tickets[i]))
	{
	  warn++;
	  shishi_ticketset_remove (ticketset, i);
	}
      else
	i++;
    }

  if (VERBOSE(ticketset->handle) && warn)
    shishi_warn (ticketset->handle,
		 ngettext ("removed %d expired ticket\n",
			   "removed %d expired tickets\n", warn), warn);

  return SHISHI_OK;
}

/**
 * shishi_ticketset_to_file:
 * @ticketset: ticket set handle as allocated by shishi_ticketset().
 * @filename: filename to write tickets to.
 *
 * Write tickets in set to file.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_ticketset_to_file (Shishi_ticketset * ticketset,
			  const char *filename)
{
  FILE *fh;
  int res;

  fh = fopen (filename, "w");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  res = shishi_ticketset_write (ticketset, fh);
  if (res != SHISHI_OK)
    {
      fclose (fh);
      return res;
    }

  res = fclose (fh);
  if (res != 0)
    return SHISHI_FCLOSE_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_ticketset_print_for_service:
 * @ticketset: ticket set handle as allocated by shishi_ticketset().
 * @fh: file descriptor to print to.
 * @service: service to limit tickets printed to, or NULL.

 * Print description of tickets for specified service to file
 * descriptor.  If service is NULL, all tickets are printed.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_ticketset_print_for_service (Shishi_ticketset * ticketset,
				    FILE * fh, char *service)
{
  int res;
  int found;
  int i;

  found = 0;
  for (i = 0; i < shishi_ticketset_size (ticketset); i++)
    {
      Shishi_ticket *ticket = shishi_ticketset_get (ticketset, i);

      if (service)
	{
	  char *buf;
	  int buflen;

	  buflen = strlen (service) + 1;
	  buf = malloc (buflen);
	  if (buf == NULL)
	    {
	      res = SHISHI_MALLOC_ERROR;
	      goto done;
	    }

	  res = shishi_ticket_server (ticket, buf, &buflen);
	  if (res != SHISHI_OK)
	    {
	      free (buf);
	      continue;
	    }
	  buf[buflen] = '\0';

	  if (strcmp (service, buf) != 0)
	    {
	      free (buf);
	      continue;
	    }

	  free (buf);
	}

      printf ("\n");
      res = shishi_ticket_pretty_print (shishi_ticketset_get (ticketset, i),
					fh);
      if (res != SHISHI_OK)
	goto done;

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

  res = 0;

done:
  if (res != SHISHI_OK)
    fprintf (stderr, "Could not list tickets: %s", shishi_strerror (res));
  return res;
}

/**
 * shishi_ticketset_print:
 * @ticketset: ticket set handle as allocated by shishi_ticketset().
 * @fh: file descriptor to print to.
 *
 * Print description of all tickets to file descriptor.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_ticketset_print (Shishi_ticketset * ticketset, FILE * fh)
{
  return shishi_ticketset_print_for_service (ticketset, fh, NULL);
}

Shishi_ticket *
shishi_ticketset_find_for_clientserveretypevalid (Shishi_ticketset * ticketset,
						  const char *client,
						  const char *server,
						  int etype,
						  int valid)
{
  int i;

  if (VERBOSE(ticketset->handle))
    fprintf (stderr, "Searching tickets for client `%s' and server `%s'\n",
	     client, server);

  for (i = 0; i < ticketset->ntickets; i++)
    {
      if (!shishi_ticket_server_p (ticketset->tickets[i], server))
	continue;

      if (valid)
	if (!shishi_ticket_valid_now_p (ticketset->tickets[i]))
	  continue;

      if (etype != -1 &&
	  !shishi_ticket_keytype_p (ticketset->tickets[i], etype))
	continue;

      return ticketset->tickets[i];
    }

  return NULL;
}

Shishi_ticket *
shishi_ticketset_find_for_clientserver (Shishi_ticketset * ticketset,
					const char *client,
					const char *server)
{
  return shishi_ticketset_find_for_clientserveretypevalid
    (ticketset, shishi_principal_default (ticketset->handle), server, -1, 1);
}

Shishi_ticket *
shishi_ticketset_find_for_clientserver_all (Shishi_ticketset * ticketset,
					    const char *client,
					    const char *server)
{
  return shishi_ticketset_find_for_clientserveretypevalid
    (ticketset, shishi_principal_default (ticketset->handle), server, -1, 0);
}

Shishi_ticket *
shishi_ticketset_find_for_serveretype (Shishi_ticketset * ticketset,
				       const char *server,
				       int etype)
{
  return shishi_ticketset_find_for_clientserveretypevalid
    (ticketset, shishi_principal_default (ticketset->handle),
     server, etype, 1);
}

Shishi_ticket *
shishi_ticketset_find_for_server (Shishi_ticketset * ticketset,
				  const char *server)
{
  return shishi_ticketset_find_for_clientserver
    (ticketset, shishi_principal_default (ticketset->handle), server);
}

Shishi_ticket *
shishi_ticketset_find_for_server_all (Shishi_ticketset * ticketset,
				      const char *server)
{
  return shishi_ticketset_find_for_clientserver_all
    (ticketset, shishi_principal_default (ticketset->handle), server);
}

Shishi_ticket *
shishi_ticketset_get_for_clientserveretype (Shishi_ticketset * ticketset,
					    const char *client,
					    const char *server,
					    int etype)
{
  Shishi_tgs *tgs;
  Shishi_ticket *tgt;
  Shishi_ticket *tkt = NULL;
  char *tgtname;
  int rc;

  tkt = shishi_ticketset_find_for_clientserveretypevalid (ticketset,
							  client, server,
							  etype, 1);
  if (tkt)
    return tkt;

  shishi_asprintf(&tgtname, "krbtgt/%s",
		  shishi_realm_default (ticketset->handle));

  tgt = shishi_ticketset_find_for_clientserver (ticketset,
						       client, tgtname);
  if (tgt == NULL)
    {
      Shishi_as *as;

      rc = shishi_as (ticketset->handle, &as);
      if (rc == SHISHI_OK)
	rc = shishi_as_sendrecv (as);
      if (rc == SHISHI_OK)
	rc = shishi_as_rep_process (as, NULL, NULL);
      if (rc != SHISHI_OK)
	{
	  printf ("AS exchange failed: %s\n%s\n", shishi_strerror (rc),
		  shishi_strerror_details (ticketset->handle));
	  if (rc == SHISHI_GOT_KRBERROR)
	    shishi_krberror_pretty_print(ticketset->handle, stdout,
					 shishi_as_krberror(as));
	  return NULL;
	}

      tgt = shishi_as_ticket (as);

      if (VERBOSEASN1(ticketset->handle))
	{
	  shishi_kdcreq_print (ticketset->handle, stdout, shishi_as_req (as));
	  shishi_kdcrep_print (ticketset->handle, stdout, shishi_as_rep (as));
	  shishi_ticket_pretty_print (tgt, stdout);
	}

      rc = shishi_ticketset_add (ticketset, tgt);
      if (rc != SHISHI_OK)
	printf ("Could not add ticket: %s", shishi_strerror (rc));

      if (!tgt)
	return NULL;
    }

  rc = shishi_tgs (ticketset->handle, &tgs);
  shishi_tgs_tgticket_set(tgs, tgt);
  if (rc == SHISHI_OK)
    rc = shishi_tgs_set_server (tgs, server);
  if (rc == SHISHI_OK)
    rc = shishi_tgs_req_build (tgs);
  if (rc == SHISHI_OK)
    rc = shishi_tgs_sendrecv (tgs);
  if (rc == SHISHI_OK)
    rc = shishi_tgs_rep_process (tgs);
  if (rc != SHISHI_OK)
    {
      printf ("TGS exchange failed: %s\n%s\n", shishi_strerror (rc),
	      shishi_strerror_details (ticketset->handle));
      if (rc == SHISHI_GOT_KRBERROR)
	shishi_krberror_pretty_print(ticketset->handle, stdout,
				     shishi_tgs_krberror(tgs));
      return NULL;
    }

  tkt = shishi_tgs_ticket (tgs);

  if (VERBOSEASN1(ticketset->handle))
    {
      shishi_authenticator_print
	(ticketset->handle, stdout,
	 shishi_ap_authenticator(shishi_tgs_ap (tgs)));
      shishi_apreq_print
	(ticketset->handle, stdout, shishi_ap_req(shishi_tgs_ap (tgs)));
      shishi_kdcreq_print (ticketset->handle, stdout, shishi_tgs_req (tgs));
      shishi_kdcrep_print (ticketset->handle, stdout, shishi_tgs_rep (tgs));
      shishi_ticket_pretty_print (tkt, stdout);
    }

  rc = shishi_ticketset_add (ticketset, tkt);
  if (rc != SHISHI_OK)
    printf ("Could not add ticket: %s", shishi_strerror (rc));

  return tkt;
}

Shishi_ticket *
shishi_ticketset_get_for_clientserver (Shishi_ticketset * ticketset,
				       const char *client,
				       const char *server)
{
  return shishi_ticketset_get_for_clientserveretype
    (ticketset, shishi_principal_default (ticketset->handle), server, -1);
}

Shishi_ticket *
shishi_ticketset_get_for_server (Shishi_ticketset * ticketset,
				 const char *server)
{
  return shishi_ticketset_get_for_clientserver
    (ticketset, shishi_principal_default (ticketset->handle), server);
}

Shishi_ticket *
shishi_ticketset_get_for_serveretype (Shishi_ticketset * ticketset,
				      const char *server,
				      int etype)
{
  return shishi_ticketset_get_for_clientserveretype
    (ticketset, shishi_principal_default (ticketset->handle), server, etype);
}

/**
 * shishi_ticketset_done:
 * @ticketset: ticket set handle as allocated by shishi_ticketset().
 *
 * Deallocates all resources associated with ticket set.  The ticket
 * set handle must not be used in calls to other shishi_ticketset_*()
 * functions after this.
 **/
void
shishi_ticketset_done (Shishi_ticketset ** ticketset)
{
  Shishi_ticketset *tset;

  if (!ticketset || !*ticketset)
    return;

  tset = *ticketset;

  if (tset->tickets)
    free (tset->tickets);
  free (tset);

  return;
}

Shishi_ticketset *
shishi_ticketset_default (Shishi * handle)
{
  if (handle->ticketset == NULL &&
      (shishi_ticketset (handle, &handle->ticketset) != SHISHI_OK))
    handle->ticketset = NULL;

  return handle->ticketset;
}
