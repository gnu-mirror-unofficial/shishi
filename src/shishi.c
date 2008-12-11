/* shishi.c --- Shishi command line interface.
 * Copyright (C) 2002, 2003, 2004, 2006, 2007, 2008  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>

/* Get i18n. */
#include <locale.h>
#include <gettext.h>
#define _(String) gettext (String)

#include <shishi.h>

/* Gnulib files. */
#include "progname.h"
#include "error.h"
#include "version-etc.h"

#include "shishi_cmd.h"

const char version_etc_copyright[] =
  /* Do *not* mark this string for translation.  %s is a copyright
     symbol suitable for this locale, and %d is the copyright
     year.  */
  "Copyright %s %d Simon Josefsson.";

static void
usage (int status) __attribute__ ((__noreturn__));

static void
usage (int status)
{
  if (status != EXIT_SUCCESS)
    fprintf (stderr, _("Try `%s --help' for more information.\n"),
	     program_name);
  else
    {
      cmdline_parser_print_help ();
      /* TRANSLATORS: The placeholder indicates the bug-reporting address
	 for this package.  Please add _another line_ saying
	 "Report translation bugs to <...>\n" with the address for translation
	 bugs (typically your translation team's web or email address).  */
      printf (_("\nMandatory arguments to long options are "
		"mandatory for short options too.\n\nReport bugs to <%s>.\n"),
	      PACKAGE_BUGREPORT);
    }
  exit (status);
}

int
main (int argc, char *argv[])
{
  struct gengetopt_args_info args;
  time_t starttime, endtime, renew_till;
  Shishi *sh;
  int rc;

  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);
  set_program_name (argv[0]);

  if (cmdline_parser (argc, argv, &args) != 0)
    usage (EXIT_FAILURE);

  if (args.version_given)
    {
      version_etc (stdout, "shishi", PACKAGE_NAME, VERSION,
		   "Simon Josefsson", (char *) NULL);
      return EXIT_SUCCESS;
    }

  if (args.inputs_num > 2 ||
      args.destroy_given + args.list_given + args.renew_given > 1)
    {
      error (0, 0, _("too many arguments"));
      usage (EXIT_FAILURE);
    }

  if (args.help_given)
    usage (EXIT_SUCCESS);

  rc = shishi_init_with_paths (&sh, args.ticket_file_arg,
			       args.system_configuration_file_arg,
			       args.configuration_file_arg);
  if (rc == SHISHI_HANDLE_ERROR)
    error (EXIT_FAILURE, 0, _("Could not initialize libshishi."));

  rc = shishi_cfg_clientkdcetype_set (sh, args.encryption_type_arg);
  if (rc != SHISHI_OK)
    error (EXIT_FAILURE, 0, _("Could not set encryption types: %s"),
	   shishi_strerror (rc));

  if (args.inputs_num > 0)
    {
      rc = shishi_parse_name (sh, args.inputs[0],
			      (args.client_name_arg ? NULL :
			       &args.client_name_arg),
			      (args.realm_arg ? NULL : &args.realm_arg));

      if (rc != SHISHI_OK)
	error (EXIT_FAILURE, 0,
	       _("Could not parse client principal \"%s\": %s"),
	       args.inputs[0], shishi_strerror (rc));
    }

  if (args.inputs_num > 1)
    {
      rc = shishi_parse_name (sh, args.inputs[1],
			      (args.server_name_arg ? NULL :
			       &args.server_name_arg),
			      (args.realm_arg ? NULL : &args.realm_arg));

      if (rc != SHISHI_OK)
	error (EXIT_FAILURE, 0,
	       _("Could not parse server principal \"%s\": %s"),
	       args.inputs[1], shishi_strerror (rc));
    }

  rc = shishi_cfg (sh, args.library_options_arg);
  if (rc != SHISHI_OK)
    error (EXIT_FAILURE, 0, _("Could not read library options: %s"),
	   shishi_strerror (rc));

  if (args.verbose_given > 0)
    shishi_cfg (sh, "verbose");
  if (args.verbose_given > 1)
    shishi_cfg (sh, "verbose-noise");
  if (args.verbose_given > 2)
    shishi_cfg (sh, "verbose-asn1");
  if (args.verbose_given > 3)
    shishi_cfg (sh, "verbose-crypto");
  if (args.verbose_given > 4)
    shishi_cfg (sh, "verbose-crypto-noise");

  if (args.starttime_arg)
    {
      starttime = shishi_get_date (args.starttime_arg, NULL);
      if (starttime == -1)
	error (EXIT_FAILURE, 0, _("Invalid --starttime date `%s'"),
	       args.starttime_arg);
    }
  else
    starttime = time (NULL);

  if (args.endtime_arg)
    {
      endtime = shishi_get_date (args.endtime_arg, &starttime);
      if (endtime == -1)
	error (EXIT_FAILURE, 0, _("Invalid --endtime date `%s'"),
	       args.starttime_arg);
    }
  else
    endtime = 0;

  if (args.renew_till_arg)
    {
      renew_till = shishi_get_date (args.renew_till_arg, &starttime);
      if (renew_till == -1)
	error (EXIT_FAILURE, 0, _("Invalid --renew-till date `%s'"),
	       args.renew_till_arg);
    }
  else
    renew_till = 0;

  if (args.client_name_arg)
    shishi_principal_default_set (sh, args.client_name_arg);

  if (args.realm_arg)
    shishi_realm_default_set (sh, args.realm_arg);

  if (!args.ticket_granter_arg)
    asprintf (&args.ticket_granter_arg, "krbtgt/%s",
	      shishi_realm_default (sh));

  if (args.list_flag)
    {
      if (!args.quiet_flag)
	printf (_("Tickets in `%s':\n"), shishi_tkts_default_file (sh));

      rc = shishi_tkts_print_for_service (shishi_tkts_default (sh),
					  stdout, args.server_name_arg);
      if (rc != SHISHI_OK)
	error (EXIT_FAILURE, 0, _("Could not list tickets: %s"),
	       shishi_strerror (rc));
    }
  else if (args.destroy_flag)
    {
      int i, removed = 0;

      for (i = 0; i < shishi_tkts_size (shishi_tkts_default (sh)); i++)
	{
	  if (args.server_name_arg &&
	      !shishi_tkt_server_p (shishi_tkts_nth (shishi_tkts_default (sh),
						     i),
				    args.server_name_arg))
	    continue;

	  if (args.verbose_given)
	    {
	      printf (_("Removing ticket:\n"));
	      shishi_tkt_pretty_print (shishi_tkts_nth
				       (shishi_tkts_default (sh), i), stdout);
	    }

	  rc = shishi_tkts_remove (shishi_tkts_default (sh), i);
	  if (rc != SHISHI_OK)
	    error (EXIT_FAILURE, 0, _("Could not destroy ticket %d:\n%s"), i,
		   shishi_strerror (rc));

	  i--;
	  removed++;
	}

      if (!args.quiet_flag)
	{
	  if (removed == 0)
	    printf (_("No tickets removed.\n"));
	  else
	    printf (ngettext ("%d ticket removed.\n",
			      "%d tickets removed.\n", removed), removed);
	}
    }
  else if (args.renew_given)
    {
      error (EXIT_FAILURE, 0, "Command --renew not implemented.");
    }
  else
    {
      Shishi_tkt *tkt;
      Shishi_tkts_hint hint;

      memset (&hint, 0, sizeof (hint));
      hint.client = args.client_name_arg;
      hint.server = args.server_name_arg ? args.server_name_arg :
	args.ticket_granter_arg;
      hint.starttime = starttime;
      hint.endtime = endtime;
      hint.renew_till = renew_till;
      if (args.renewable_flag)
	hint.tktflags |= SHISHI_TICKETFLAGS_RENEWABLE;
      if (args.proxiable_flag)
	hint.tktflags |= SHISHI_TICKETFLAGS_PROXIABLE;
      if (args.proxy_flag)
	hint.tktflags |= SHISHI_TICKETFLAGS_PROXY;
      if (args.forwardable_flag)
	hint.tktflags |= SHISHI_TICKETFLAGS_FORWARDABLE;
      if (args.forwarded_flag)
	hint.tktflags |= SHISHI_TICKETFLAGS_FORWARDED;

      tkt = shishi_tkts_get (shishi_tkts_default (sh), &hint);
      if (!tkt)
	error (EXIT_FAILURE, 0, _("Could not get ticket as `%s' for `%s'."),
	       hint.client ? hint.client : shishi_principal_default (sh),
	       hint.server);

      shishi_tkt_pretty_print (tkt, stdout);
    }

  shishi_tkts_expire (shishi_tkts_default (sh));

  if (args.ticket_write_file_arg)
    shishi_tkts_default_file_set (sh, args.ticket_write_file_arg);

  shishi_done (sh);

  return EXIT_SUCCESS;
}
