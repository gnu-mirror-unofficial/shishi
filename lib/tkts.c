/* tkts.c	Ticket set handling.
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

/* XXX how to generalize shishi_tkts_{get,find}_tkt_for_*()??  unclean
   with lots of different functions... A: getaddrinfo() like
   approach. */

#include "internal.h"

struct Shishi_tkts
{
  Shishi *handle;
  Shishi_tkt **tkts;
  int ntkts;
};

/**
 * shishi_tkts_default_file_guess:
 *
 * Guesses the default ticket filename; it is $HOME/.shishi/tickets.
 *
 * Return value: Returns default tkts filename as a string that
 * has to be deallocated with free() by the caller.
 **/
char *
shishi_tkts_default_file_guess (void)
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
 * shishi_tkts_default_file:
 * @handle: Shishi library handle create by shishi_init().
 *
 * Return value: Returns the default ticket set filename used in the
 * library.  (Not a copy of it, so don't modify or deallocate it.)
 **/
const char *
shishi_tkts_default_file (Shishi * handle)
{
  if (!handle->tktsdefaultfile)
    {
      char *p;

      p = shishi_tkts_default_file_guess ();
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
    handle->tktsdefaultfile = strdup (tktsfile);
  else
    handle->tktsdefaultfile = NULL;
}

/**
 * shishi_tkts:
 * @handle: shishi handle as allocated by shishi_init().
 * @tkts: output pointer to newly allocated tkts handle.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_tkts (Shishi * handle, Shishi_tkts ** tkts)
{
  *tkts = malloc (sizeof (**tkts));
  if (*tkts == NULL)
    return SHISHI_MALLOC_ERROR;
  memset (*tkts, 0, sizeof (**tkts));

  (*tkts)->handle = handle;

  return SHISHI_OK;
}

/**
 * shishi_tkts_size:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 *
 * Return value: Returns number of tickets stored in ticket set.
 **/
int
shishi_tkts_size (Shishi_tkts * tkts)
{
  return tkts->ntkts;
}

/**
 * shishi_tkts_get:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @ticketno: integer indicating requested ticket in ticket set.
 *
 * Return value: Returns a ticket handle to the ticketno:th ticket in
 * the ticket set, or NULL if ticket set is invalid or ticketno is out
 * of bounds.  The first ticket is ticketno 0, the second ticketno 1,
 * and so on.
 **/
Shishi_tkt *
shishi_tkts_get (Shishi_tkts * tkts, int ticketno)
{
  if (tkts == NULL || ticketno >= tkts->ntkts)
    return NULL;

  return tkts->tkts[ticketno];
}

/**
 * shishi_tkts_remove:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @ticketnum: ticket number of ticket in the set to remove.  The
 * first ticket is ticket number 0.
 *
 * Return value: Returns SHISHI_OK if succesful or if ticketno
 * larger than size of ticket set.
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
      tkts->tkts = realloc (tkts->tkts, sizeof (*tkts->tkts) * tkts->ntkts);
      if (tkts->tkts == NULL)
	return SHISHI_MALLOC_ERROR;
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
 * @ticket: ticket to be added to ticket set.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_tkts_add (Shishi_tkts * tkts, Shishi_tkt * tkt)
{
  if (!tkt)
    return SHISHI_INVALID_TICKET;

  if (tkts->ntkts++ == 0)
    tkts->tkts = malloc (sizeof (*tkts->tkts));
  else
    tkts->tkts = realloc (tkts->tkts, sizeof (*tkts->tkts) * tkts->ntkts);
  if (tkts->tkts == NULL)
    return SHISHI_MALLOC_ERROR;

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
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_tkts_new (Shishi_tkts * tkts,
		 Shishi_asn1 ticket, Shishi_asn1 enckdcreppart,
		 Shishi_asn1 kdcrep)
{
  Shishi_tkt *tkt;
  int res;

  tkt = shishi_tkt2 (tkts->handle, ticket, enckdcreppart, kdcrep);
  if (tkt == NULL)
    return SHISHI_MALLOC_ERROR;

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

      res = shishi_tkts_new (tkts, ticket, enckdcreppart, kdcrep);
      if (res != SHISHI_OK)
	break;

      if (VERBOSE (tkts->handle))
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
    return SHISHI_FCLOSE_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_tkts_write:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @filename: filename to write tickets to.
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

  for (i = 0; i < tkts->ntkts; i++)
    {
      res = shishi_kdcrep_print
	(tkts->handle, fh, shishi_tkt_kdcrep (tkts->tkts[i]));
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (tkts->handle,
			       "Could not print ticket: %s\n",
			       shishi_strerror_details (tkts->handle));
	  return res;
	}

      res = shishi_enckdcreppart_print
	(tkts->handle, fh, shishi_tkt_enckdcreppart (tkts->tkts[i]));
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (tkts->handle,
			       "Could not print ticket: %s\n",
			       shishi_strerror_details (tkts->handle));
	  return res;
	}

      res = shishi_ticket_print (tkts->handle, fh,
				 shishi_tkt_ticket (tkts->tkts[i]));
      if (res != SHISHI_OK)
	{
	  shishi_error_printf (tkts->handle,
			       "Could not print ticket: %s\n",
			       shishi_strerror_details (tkts->handle));
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

  while (i < tkts->ntkts)
    {
      if (!shishi_tkt_valid_now_p (tkts->tkts[i]))
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
    return SHISHI_FCLOSE_ERROR;

  return SHISHI_OK;
}

/**
 * shishi_tkts_print_for_service:
 * @tkts: ticket set handle as allocated by shishi_tkts().
 * @fh: file descriptor to print to.
 * @service: service to limit tickets printed to, or NULL.

 * Print description of tickets for specified service to file
 * descriptor.  If service is NULL, all tickets are printed.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_tkts_print_for_service (Shishi_tkts * tkts, FILE * fh, char *service)
{
  int res;
  int found;
  int i;

  found = 0;
  for (i = 0; i < shishi_tkts_size (tkts); i++)
    {
      Shishi_tkt *tkt = shishi_tkts_get (tkts, i);

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

	  res = shishi_tkt_server (tkt, buf, &buflen);
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
      res = shishi_tkt_pretty_print (shishi_tkts_get (tkts, i), fh);
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

Shishi_tkt *
shishi_tkts_find_for_clientserveretypevalid (Shishi_tkts *
					     tkts,
					     const char *client,
					     const char *server,
					     int etype, int valid)
{
  int i;

  if (VERBOSE (tkts->handle))
    fprintf (stderr, "Searching tickets for client `%s' and server `%s'\n",
	     client, server);

  for (i = 0; i < tkts->ntkts; i++)
    {
      if (!shishi_tkt_server_p (tkts->tkts[i], server))
	continue;

      if (!shishi_tkt_cnamerealm_p (tkts->tkts[i], client))
	continue;

      if (valid)
	if (!shishi_tkt_valid_now_p (tkts->tkts[i]))
	  continue;

      if (etype != -1 && !shishi_tkt_keytype_p (tkts->tkts[i], etype))
	continue;

      return tkts->tkts[i];
    }

  return NULL;
}

Shishi_tkt *
shishi_tkts_find_for_clientserver (Shishi_tkts * tkts,
				   const char *client, const char *server)
{
  return shishi_tkts_find_for_clientserveretypevalid
    (tkts, shishi_principal_default (tkts->handle), server, -1, 1);
}

Shishi_tkt *
shishi_tkts_find_for_clientserver_all (Shishi_tkts * tkts,
				       const char *client, const char *server)
{
  return shishi_tkts_find_for_clientserveretypevalid
    (tkts, shishi_principal_default (tkts->handle), server, -1, 0);
}

Shishi_tkt *
shishi_tkts_find_for_serveretype (Shishi_tkts * tkts,
				  const char *server, int etype)
{
  return shishi_tkts_find_for_clientserveretypevalid
    (tkts, shishi_principal_default (tkts->handle), server, etype, 1);
}

Shishi_tkt *
shishi_tkts_find_for_server (Shishi_tkts * tkts, const char *server)
{
  return shishi_tkts_find_for_clientserver
    (tkts, shishi_principal_default (tkts->handle), server);
}

Shishi_tkt *
shishi_tkts_find_for_server_all (Shishi_tkts * tkts, const char *server)
{
  return shishi_tkts_find_for_clientserver_all
    (tkts, shishi_principal_default (tkts->handle), server);
}

Shishi_tkt *
shishi_tkts_get_for_clientserverpasswdetype (Shishi_tkts *
					     tkts,
					     const char *client,
					     const char *server,
					     const char *passwd, int etype)
{
  Shishi_tgs *tgs;
  Shishi_tkt *tgt;
  Shishi_tkt *tkt = NULL;
  char *tgtname;
  int rc;

  tkt = shishi_tkts_find_for_clientserveretypevalid (tkts,
						     client, server,
						     etype, 1);
  if (tkt)
    return tkt;

  shishi_asprintf (&tgtname, "krbtgt/%s",
		   shishi_realm_default (tkts->handle));

  tgt = shishi_tkts_find_for_clientserver (tkts, client, tgtname);
  if (tgt == NULL)
    {
      Shishi_as *as;

      rc = shishi_as (tkts->handle, &as);
      if (rc == SHISHI_OK)
	rc = shishi_as_sendrecv (as);
      if (rc == SHISHI_OK)
	rc = shishi_as_rep_process (as, NULL, passwd);
      if (rc != SHISHI_OK)
	{
	  printf ("AS exchange failed: %s\n%s\n", shishi_strerror (rc),
		  shishi_strerror_details (tkts->handle));
	  if (rc == SHISHI_GOT_KRBERROR)
	    shishi_krberror_pretty_print (tkts->handle, stdout,
					  shishi_as_krberror (as));
	  return NULL;
	}

      tgt = shishi_as_tkt (as);

      if (VERBOSEASN1 (tkts->handle))
	{
	  shishi_kdcreq_print (tkts->handle, stdout, shishi_as_req (as));
	  shishi_kdcrep_print (tkts->handle, stdout, shishi_as_rep (as));
	  shishi_tkt_pretty_print (tgt, stdout);
	}

      rc = shishi_tkts_add (tkts, tgt);
      if (rc != SHISHI_OK)
	printf ("Could not add ticket: %s", shishi_strerror (rc));

      if (!tgt)
	return NULL;
    }

  rc = shishi_tgs (tkts->handle, &tgs);
  shishi_tgs_tgtkt_set (tgs, tgt);
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
	      shishi_strerror_details (tkts->handle));
      if (rc == SHISHI_GOT_KRBERROR)
	shishi_krberror_pretty_print (tkts->handle, stdout,
				      shishi_tgs_krberror (tgs));
      return NULL;
    }

  tkt = shishi_tgs_tkt (tgs);

  if (VERBOSEASN1 (tkts->handle))
    {
      shishi_authenticator_print
	(tkts->handle, stdout, shishi_ap_authenticator (shishi_tgs_ap (tgs)));
      shishi_apreq_print
	(tkts->handle, stdout, shishi_ap_req (shishi_tgs_ap (tgs)));
      shishi_kdcreq_print (tkts->handle, stdout, shishi_tgs_req (tgs));
      shishi_kdcrep_print (tkts->handle, stdout, shishi_tgs_rep (tgs));
      shishi_tkt_pretty_print (tkt, stdout);
    }

  rc = shishi_tkts_add (tkts, tkt);
  if (rc != SHISHI_OK)
    printf ("Could not add ticket: %s", shishi_strerror (rc));

  return tkt;
}

Shishi_tkt *
shishi_tkts_get_for_clientserveretype (Shishi_tkts * tkts,
				       const char *client,
				       const char *server, int etype)
{
  return shishi_tkts_get_for_clientserverpasswdetype (tkts,
						      client,
						      server, NULL, etype);
}

Shishi_tkt *
shishi_tkts_get_for_clientserver (Shishi_tkts * tkts,
				  const char *client, const char *server)
{
  return shishi_tkts_get_for_clientserveretype
    (tkts, shishi_principal_default (tkts->handle), server, -1);
}

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
  char buf[HOST_NAME_MAX];
  int ret;

  strcpy (buf, service);
  strcat (buf, "/");

  ret = gethostname (&buf[strlen (service) + 1],
		     sizeof (buf) - strlen (service) - 1);
  buf[sizeof (buf) - 1] = '\0';

  if (ret != 0)
    strcpy (&buf[strlen (service) + 1], "localhost");

  return shishi_tkts_get_for_clientserverpasswdetype
    (tkts, shishi_principal_default (tkts->handle), buf, passwd, -1);
}

Shishi_tkt *
shishi_tkts_get_for_serveretype (Shishi_tkts * tkts,
				 const char *server, int etype)
{
  return shishi_tkts_get_for_clientserveretype
    (tkts, shishi_principal_default (tkts->handle), server, etype);
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
  Shishi_tkts *tset;

  if (!tkts || !*tkts)
    return;

  tset = *tkts;

  if (tset->tkts)
    free (tset->tkts);
  free (tset);

  return;
}

Shishi_tkts *
shishi_tkts_default (Shishi * handle)
{
  if (handle->tkts == NULL &&
      (shishi_tkts (handle, &handle->tkts) != SHISHI_OK))
    handle->tkts = NULL;

  return handle->tkts;
}
