/* shishi.c	command line interface to shishi
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#if defined HAVE_DECL_H_ERRNO && !HAVE_DECL_H_ERRNO
/* extern int h_errno; */
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
#  include <stdint.h>
# endif
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#if HAVE_STRING_H
# if !STDC_HEADERS && HAVE_MEMORY_H
#  include <memory.h>
# endif
# include <string.h>
#endif
#if HAVE_STRINGS_H
# include <strings.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif

#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include "getdate.h"
#include "xalloc.h"
#include "error.h"

#include <argp.h>
#include <gettext.h>
#include <shishi.h>

#define _(String) gettext (String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

/* Long parameters only */
enum
{
  OPTION_REQUEST = 300,
  OPTION_SENDRECV,
  OPTION_RESPONSE,
  OPTION_WRITE_AP_REQUEST_FILE,
  OPTION_WRITE_AUTHENTICATOR_FILE,
  OPTION_WRITE_REQUEST_FILE,
  OPTION_WRITE_RESPONSE_FILE,
  OPTION_READ_REQUEST_FILE,
  OPTION_READ_RESPONSE_FILE,
  OPTION_SERVER,
  OPTION_CLIENT,
  OPTION_CLIENT_NAME,
  OPTION_REALM,
  OPTION_SERVER_NAME,
  OPTION_TICKET_GRANTER,
  OPTION_FORCE_AS,
  OPTION_FORCE_TGS,
  OPTION_LIST,
  OPTION_DESTROY,
  OPTION_RENEW,
  OPTION_RENEWABLE,
  OPTION_PROXIABLE,
  OPTION_PROXY,
  OPTION_FORWARDABLE,
  OPTION_FORWARDED,
  OPTION_STARTTIME,
  OPTION_ENDTIME,
  OPTION_RENEW_TILL,
  OPTION_CFG_SYSTEM,
  OPTION_CFG_USER,
  OPTION_WRITE_TICKET_FILE
};

#define TYPE_TEXT_NAME "text"
#define TYPE_DER_NAME "der"
#define TYPE_HEX_NAME "hex"
#define TYPE_BASE64_NAME "base64"
#define TYPE_BINARY_NAME "binary"

struct arguments
{
  int silent, verbose;
  char *etypes;
  char *lib_options;
  int command;
  char *ticketfile;
  char *ticketwritefile;
  char *systemcfgfile;
  char *usercfgfile;
  const char *client;
  const char *crealm;
  const char *cname;
  const char *sname;
  const char *srealm;
  const char *server;
  char *tgtname;
  int forceas_p;
  int forcetgs_p;
  char *servername;
  int renewable;
  int proxiable;
  int proxy;
  int forwardable;
  int forwarded;
  time_t starttime;
  char *endtime_str;
  time_t endtime;
  char *renew_till_str;
  time_t renew_till;
  int algorithm;
};

const char *program_name = PACKAGE;
const char *argp_program_version = PACKAGE_STRING;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  struct arguments *arguments = state->input;

  switch (key)
    {
    case 'q':
      arguments->silent = 1;
      break;

    case 'v':
      arguments->verbose++;
      break;

    case 'o':
      arguments->lib_options = arg;
      break;

    case OPTION_WRITE_TICKET_FILE:
      arguments->ticketwritefile = strdup (arg);
      break;

    case 'E':
      arguments->etypes = strdup (arg);
      break;

    case OPTION_CFG_SYSTEM:
      arguments->systemcfgfile = strdup (arg);
      break;

    case OPTION_CFG_USER:
      arguments->usercfgfile = strdup (arg);
      break;

    case 'c':
      arguments->ticketfile = strdup (arg);
      break;

    case OPTION_CLIENT_NAME:
      arguments->cname = strdup (arg);
      break;

    case 'e':
    case OPTION_ENDTIME:
      arguments->endtime_str = strdup (arg);
      break;

    case OPTION_FORWARDABLE:
      arguments->forwardable = 1;
      break;

    case OPTION_FORWARDED:
      arguments->forwarded = 1;
      break;

    case OPTION_PROXIABLE:
      arguments->proxiable = 1;
      break;

    case OPTION_PROXY:
      arguments->proxy = 1;
      break;

    case OPTION_REALM:
      arguments->crealm = strdup (arg);
      break;

    case 'R':
    case OPTION_RENEW:
      arguments->command = OPTION_RENEW;
      break;

    case OPTION_RENEW_TILL:
      arguments->renew_till_str = strdup (arg);
      /* fall through */

    case OPTION_RENEWABLE:
      arguments->renewable = 1;
      break;

    case 's':
    case OPTION_STARTTIME:
      arguments->starttime = get_date (arg, NULL);
      if (arguments->starttime == -1)
	argp_error (state, _("invalid --starttime date `%s'"), arg);
      break;

    case OPTION_SERVER_NAME:
      arguments->sname = strdup (arg);
      break;

    case OPTION_FORCE_AS:
      arguments->forceas_p = 1;
      break;

    case OPTION_FORCE_TGS:
      arguments->forcetgs_p = 1;
      break;

    case OPTION_TICKET_GRANTER:
      arguments->tgtname = strdup (arg);
      break;

    case 'l':
    case OPTION_LIST:
      arguments->command = OPTION_LIST;
      break;

    case 'd':
    case OPTION_DESTROY:
      arguments->command = OPTION_DESTROY;
      break;

    case ARGP_KEY_ARG:
      if (arguments->server && arguments->client)
	argp_error (state, _("Too many arguments: `%s'"), arg);
      if (arguments->client)
	arguments->server = strdup (arg);
      else
	arguments->client = strdup (arg);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp_option options[] = {

  {0, 0, 0, 0, "If no command is given, Shishi try to make sure you have a "
   "ticket granting ticket for the default realm, and then display it.", 0},

  {"client-name", OPTION_CLIENT_NAME, "NAME", 0,
   "Client name. Default is login username.", 10},

  {"destroy", 'd', 0, 0,
   "Destroy tickets in local cache, subject to --client-name and "
   "--server-name limiting.", 0},

  {"encryption-type", 'E', "ETYPE,[ETYPE...]", 0,
   "Encryption types to use.  ETYPE is either registered name or integer.",
   0},

  {"force-as", OPTION_FORCE_AS, 0, 0,
   "Force AS mode. Default is to use TGS iff a TGT is found.", 0},

  {"force-tgs", OPTION_FORCE_TGS, 0, 0,
   "Force TGS mode. Default is to use TGS iff a TGT is found.", 0},

  {"endtime", 'e', "STRING", 0,
   "Specify when ticket validity should expire.  The time syntax may be "
   "relative (to the start time), such as \"20 hours\", or absolute, "
   "such as \"2001-02-03 04:05:06 CET\". The default is 8 hours after "
   "the start time.", 0},

  {"forwardable", OPTION_FORWARDABLE, 0, 0,
   "Get a forwardable ticket, i.e., one that can be used to get forwarded "
   "tickets.", 0},

  {"forwarded", OPTION_FORWARDED, 0, 0,
   "Get a forwarded ticket.", 0},

  {"list", 'l', 0, 0,
   "List tickets in local cache, subject to --server-name limiting.", 0},

  {"proxiable", OPTION_PROXIABLE, 0, 0,
   "Get a proxiable ticket, i.e., one that can be used to get proxy "
   "tickets.", 0},

  {"proxy", OPTION_PROXY, 0, 0,
   "Get a proxy ticket.", 0},

  {"renew", 'R', 0, 0,
   "Renew ticket.  Use --server-name to specify ticket, default is the "
   "most recent renewable ticket granting ticket for the default realm.", 0},

  {"renewable", OPTION_RENEWABLE, 0, 0,
   "Get a renewable ticket.", 0},

  {"renew-till", OPTION_RENEW_TILL, "STRING", 0,
   "Specify renewable life of ticket.  Implies --renewable.  Accepts same "
   "time syntax as --endtime.  If --renewable is specified, the default is 1 "
   "week after the start time.", 0},

  {"realm", OPTION_REALM, "REALM", 0,
   "Realm of server. Default is DNS domain of local host. For AS, this also "
   "indicates realm of client.", 0},

  {"server", OPTION_SERVER, "[FAMILY:]ADDRESS:SERVICE/TYPE", 0,
   "Send all requests to HOST instead of using normal logic to locate "
   "KDC addresses (discouraged).", 0},

  {"server-name", OPTION_SERVER_NAME, "NAME", 0,
   "Server name. Default is \"krbtgt/REALM\" where REALM is server "
   "realm (see --realm).", 0},

  {"starttime", 's', "STRING", 0,
   "Specify when ticket should start to be valid.  Accepts same time syntax "
   "as --endtime. The default is to become valid immediately.", 0},

  {"ticket-granter", OPTION_TICKET_GRANTER, "NAME", 0,
   "Service name in ticket to use for authenticating request. Only for TGS. "
   "Defaults to \"krbtgt/REALM@REALM\" where REALM is server "
   "realm (see --realm).", 0},

  /************** OTHER */

  {0, 0, 0, 0, "Other options:", 200},

  {"verbose", 'v', 0, 0,
   "Produce verbose output.  Use multiple times to increase amount of "
   "verbose output.", 0},

  {"quiet", 'q', 0, 0,
   "Don't produce any output.", 0},

  {"silent", 0, 0, OPTION_ALIAS,
   NULL, 0},

  {"system-configuration-file", OPTION_CFG_SYSTEM, "FILE", 0,
   "Read system wide configuration from file.  Default is " SYSTEMCFGFILE
   ".", 0},

  {"configuration-file", OPTION_CFG_USER, "FILE", 0,
   "Read user configuration from file.  Default is ~/.shishi/config.", 0},

  {"library-options", 'o', "STRING", 0,
   "Parse STRING as a configuration file statement.", 0},

  {"ticket-file", 'c', "FILE", 0,
   "Read tickets from FILE. Default is $HOME/.shishi/tickets.", 0},

  {"ticket-write-file", OPTION_WRITE_TICKET_FILE, "FILE", 0,
   "Write tickets to FILE.  Default is to write them back to ticket file.",
   0},

  {"CLIENT", 0, 0, OPTION_DOC | OPTION_NO_USAGE,
   "Set client name and realm from NAME.  The --client-name and --realm "
   "parameters can be used to override part of NAME.", 0},

  {"SERVER", 0, 0, OPTION_DOC | OPTION_NO_USAGE,
   "Set server name and realm from NAME.  The --server-name and "
   "--server-realm parameters can be used to override part of SERVER.", 0},

  /************** EXAMPLES */

  {0, 0, 0, 0, "Examples:", 300},

  {"shishi", 0, 0, OPTION_DOC | OPTION_NO_USAGE,
   "Get a ticket granting ticket from the default KDC server for the "
   "default user and realm.", 0},

  {"shishi jas/admin@ACCOUNTING", 0, 0, OPTION_DOC | OPTION_NO_USAGE,
   "Get a ticket for jas/admin in the ACCOUNTING realm.", 0},

  {"shishi --list --server-name=krbtgt/JOSEFSSON.ORG@JOSEFSSON.ORG",
   0, 0, OPTION_DOC | OPTION_NO_USAGE,
   "List tickets for the Ticket Granting Service in the JOSEFSSON.ORG realm.",
   0},

  {NULL, 0, 0, 0, NULL, 0}
};

static struct argp argp = {
  options,
  parse_opt,
  "[CLIENT [SERVER]] [OPTION...]\n"
    "--list [CLIENT [SERVER]]\n"
    "--destroy [CLIENT [SERVER]]\n",
  "Shishi -- A Kerberos 5 implementation",
  NULL,
  NULL,
  NULL
};

int
main (int argc, char *argv[])
{
  struct arguments arg;
  Shishi *handle;
  int rc;
  int32_t *etype;

  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  memset (&arg, 0, sizeof (arg));
  arg.algorithm = -1;
  argp_parse (&argp, argc, argv, ARGP_IN_ORDER, 0, &arg);

  rc = shishi_init_with_paths (&handle, arg.ticketfile,
			       arg.systemcfgfile, arg.usercfgfile);
  if (rc == SHISHI_HANDLE_ERROR)
    error (1, 0, "Internal error: could not initialize shishi\n");

  rc = shishi_cfg_clientkdcetype_set (handle, arg.etypes);
  if (rc != SHISHI_OK)
    error (1, 0, "Could not set encryption types: %s\n",
	   shishi_strerror (rc));

  if (arg.algorithm == -1 && shishi_cfg_clientkdcetype (handle, &etype) > 0)
    arg.algorithm = *etype;

  if (arg.client)
    {
      rc = shishi_parse_name (handle, arg.client,
			      (char **) (arg.cname ? NULL : &arg.cname),
			      (char **) (arg.crealm ? NULL : &arg.crealm));

      if (rc != SHISHI_OK)
	error (1, 0, "Could not parse principal \"%s\": %s\n", arg.client,
	       shishi_strerror (rc));
    }

  if (arg.server)
    {
      rc = shishi_parse_name (handle, arg.server,
			      (char **) (arg.sname ? NULL : &arg.sname),
			      (char **) (arg.srealm ? NULL : &arg.srealm));

      if (rc != SHISHI_OK)
	error (1, 0, "Could not parse principal \"%s\": %s\n", arg.server,
	       shishi_strerror (rc));
    }

  rc = shishi_cfg (handle, arg.lib_options);
  if (rc != SHISHI_OK)
    error (1, 0, "Could not read library options: %s\n",
	   shishi_strerror (rc));

  if (arg.verbose > 1)
    {
      rc = shishi_cfg (handle, "verbose");
      if (rc != SHISHI_OK)
	error (1, 0, "Could not make library verbose: %s\n",
	       shishi_strerror (rc));
    }

  if (arg.verbose > 2)
    {
      rc = shishi_cfg (handle, "verbose-noice");
      if (rc != SHISHI_OK)
	error (1, 0, "Could not make library verbose: %s\n",
	       shishi_strerror (rc));
    }

  if (arg.verbose > 3)
    {
      rc = shishi_cfg (handle, "verbose-asn1");
      if (rc != SHISHI_OK)
	error (1, 0, "Could not make library verbose: %s\n",
	       shishi_strerror (rc));
    }

  if (arg.verbose > 4)
    {
      rc = shishi_cfg (handle, "verbose-crypto");
      if (rc != SHISHI_OK)
	error (1, 0, "Could not make library verbose: %s\n",
	       shishi_strerror (rc));
    }

  if (arg.verbose > 5)
    {
      rc = shishi_cfg (handle, "verbose-crypto-noice");
      if (rc != SHISHI_OK)
	error (1, 0, "Could not make library verbose: %s\n",
	       shishi_strerror (rc));
    }

  if (!arg.starttime)
    arg.starttime = time (NULL);

  if (arg.endtime_str)
    {
      arg.endtime = get_date (arg.endtime_str, &arg.starttime);
      if (arg.endtime == -1)
	error (1, 0, _("invalid --endtime date `%s'"), arg.endtime_str);
    }

  if (arg.renew_till_str)
    {
      arg.renew_till = get_date (arg.renew_till_str, &arg.starttime);
      if (arg.renew_till == -1)
	error (1, 0, _("invalid --renew-till date `%s'"), arg.renew_till_str);
    }

  if (arg.cname)
    shishi_principal_default_set (handle, arg.cname);

  if (arg.crealm)
    shishi_realm_default_set (handle, arg.crealm);

  if (!arg.tgtname)
    {
      asprintf (&arg.tgtname, "krbtgt/%s", shishi_realm_default (handle));
      if (arg.tgtname == NULL)
	error (1, 0, "Could not allocate TGT name.");
    }

  rc = 1;

  switch (arg.command)
    {
    case OPTION_LIST:
      if (!arg.silent)
	printf (_("Tickets in `%s':\n"), shishi_tkts_default_file (handle));

      rc = shishi_tkts_print_for_service (shishi_tkts_default (handle),
					  stdout, arg.sname);
      if (rc != SHISHI_OK)
	fprintf (stderr, "Could not list tickets: %s", shishi_strerror (rc));
      break;

    case OPTION_DESTROY:
      {
	int i, removed = 0;
	for (i = 0; i < shishi_tkts_size (shishi_tkts_default (handle)); i++)
	  {
	    if (arg.sname &&
		!shishi_tkt_server_p (shishi_tkts_nth
				      (shishi_tkts_default (handle),
				       i), arg.sname))
	      continue;

	    if (arg.verbose)
	      {
		printf ("Removing ticket:\n");
		shishi_tkt_pretty_print (shishi_tkts_nth
					 (shishi_tkts_default
					  (handle), i), stdout);
	      }

	    rc = shishi_tkts_remove (shishi_tkts_default (handle), i);
	    if (rc != SHISHI_OK)
	      fprintf (stderr, "Could not destroy ticket %d:\n%s\n", i,
		       shishi_strerror (rc));
	    i--;
	    removed++;
	  }
	if (!arg.silent)
	  {
	    if (removed == 0)
	      printf ("No tickets removed.\n");
	    else if (removed == 1)
	      printf ("1 ticket removed.\n");
	    else
	      printf ("%d tickets removed.\n", removed);
	  }
	rc = SHISHI_OK;
      }
      break;

    case OPTION_RENEW:
      {
	Shishi_tkt *tkt;
	Shishi_tkts_hint hint;
	Shishi_tgs *tgs;

	/* This doesn't work */

	memset (&hint, 0, sizeof (hint));
	hint.client = (char *) arg.cname;
	hint.server = (char *) (arg.sname ? arg.sname : arg.tgtname);
	hint.starttime = arg.starttime;
	hint.endtime = arg.endtime;
	hint.renew_till = arg.renew_till;

	tkt = shishi_tkts_find (shishi_tkts_default (handle), &hint);
	if (!tkt)
	  {
	    fprintf (stderr, "Could not get ticket for `%s'.\n", hint.server);
	    rc = !SHISHI_OK;
	  }
	else
	  shishi_tkt_pretty_print (tkt, stdout);

	/* Get ticket using TGT ... */
	rc = shishi_tgs (handle, &tgs);
	shishi_tgs_tgtkt_set (tgs, tkt);
	if (rc == SHISHI_OK)
	  rc = shishi_tgs_set_server (tgs, hint.server);
	rc = shishi_kdcreq_options_add (handle, shishi_tgs_req (tgs),
					SHISHI_KDCOPTIONS_RENEWABLE |
					SHISHI_KDCOPTIONS_RENEW);
	if (rc == SHISHI_OK)
	  rc = shishi_asn1_write (handle, shishi_tgs_req (tgs),
				  "req-body.rtime",
				  shishi_generalize_time
				  (handle, hint.renew_till), 0);
	if (rc == SHISHI_OK)
	  rc = shishi_tgs_req_build (tgs);
	if (rc == SHISHI_OK)
	  rc = shishi_tgs_sendrecv (tgs);
	if (rc == SHISHI_OK)
	  rc = shishi_tgs_rep_process (tgs);
	if (rc != SHISHI_OK)
	  {
	    fprintf (stderr, "TGS exchange failed: %s\n%s\n",
		     shishi_strerror (rc), shishi_error (handle));
	    if (rc == SHISHI_GOT_KRBERROR)
	      shishi_krberror_pretty_print (handle, stdout,
					    shishi_tgs_krberror (tgs));
	    break;
	  }

	tkt = shishi_tgs_tkt (tgs);
	if (!tkt)
	  {
	    fprintf (stderr, "No ticket in TGS-REP?!: %s\n",
		     shishi_error (handle));
	    break;
	  }

	shishi_tkt_pretty_print (tkt, stdout);

	rc = shishi_tkts_add (shishi_tkts_default (handle), tkt);
	if (rc != SHISHI_OK)
	  fprintf (stderr, "Could not add ticket: %s", shishi_strerror (rc));
      }
      break;

    default:
      {
	Shishi_tkt *tkt;
	Shishi_tkts_hint hint;

	memset (&hint, 0, sizeof (hint));
	hint.client = (char *) arg.cname;
	hint.server = (char *) (arg.sname ? arg.sname : arg.tgtname);
	hint.starttime = arg.starttime;
	hint.endtime = arg.endtime;
	hint.renew_till = arg.renew_till;
	if (arg.renewable)
	  hint.tktflags |= SHISHI_TICKETFLAGS_RENEWABLE;
	if (arg.proxiable)
	  hint.tktflags |= SHISHI_TICKETFLAGS_PROXIABLE;
	if (arg.proxy)
	  hint.tktflags |= SHISHI_TICKETFLAGS_PROXY;
	if (arg.forwardable)
	  hint.tktflags |= SHISHI_TICKETFLAGS_FORWARDABLE;
	if (arg.forwarded)
	  hint.tktflags |= SHISHI_TICKETFLAGS_FORWARDED;

	tkt = shishi_tkts_get (shishi_tkts_default (handle), &hint);
	if (!tkt)
	  {
	    fprintf (stderr, "Could not get ticket for `%s'.\n", hint.server);
	    rc = !SHISHI_OK;
	  }
	else
	  shishi_tkt_pretty_print (tkt, stdout);
      }
      break;
    }

  shishi_tkts_expire (shishi_tkts_default (handle));

  if (arg.ticketwritefile)
    shishi_tkts_default_file_set (handle, arg.ticketwritefile);

  shishi_done (handle);

  return rc == SHISHI_OK ? 0 : 1;
}
