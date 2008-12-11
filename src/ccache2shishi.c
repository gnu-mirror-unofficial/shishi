/* ccache2shishi.c --- Print and convert MIT ccache files.
 * Copyright (C) 2006, 2007, 2008  Simon Josefsson
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
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
#include <errno.h>

/* For getuid. */
#include <sys/types.h>
#include <unistd.h>

/* Get i18n. */
#include <locale.h>
#include <gettext.h>
#define _(String) gettext (String)

#include <shishi.h>

/* Get set_program_name and program_name. */
#include "progname.h"

/* Get error. */
#include "error.h"

#include "ccache2shishi_cmd.h"

int
main (int argc, char *argv[])
{
  struct gengetopt_args_info args;
  Shishi *sh;
  const char *infile = NULL;
  const char *outfile = NULL;
  int rc;

  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);
  set_program_name (argv[0]);

  if (cmdline_parser (argc, argv, &args) != 0)
    error (EXIT_FAILURE, 0, _("Try `%s --help' for more information."),
	   program_name);

  if (args.inputs_num > 0)
    infile = args.inputs[0];

  if (args.inputs_num > 1)
    outfile = args.inputs[1];

  if (args.inputs_num > 2)
    {
      error (0, 0, _("too many arguments"));
      error (EXIT_FAILURE, 0, _("Try `%s --help' for more information."),
	     program_name);
    }

  if (args.help_given)
    {
      cmdline_parser_print_help ();
      printf (_("\nMandatory arguments to long options are "
		"mandatory for short options too.\n\nReport bugs to <%s>.\n"),
	      PACKAGE_BUGREPORT);
      return EXIT_SUCCESS;
    }

  sh = shishi ();
  if (!sh)
    error (EXIT_FAILURE, 0, _("Could not initialize libshishi."));

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

  if (!infile)
    infile = shishi_tkts_default_ccache (sh);

  if (!outfile)
    outfile = shishi_tkts_default_file (sh);

  {
    Shishi_tkts *tkts;

    rc = shishi_tkts_from_ccache_file (sh, infile, &tkts);
    if (rc != SHISHI_OK)
      error (EXIT_FAILURE, errno, "%s: %s", infile, shishi_strerror (rc));

    if (args.verbose_given)
      shishi_tkts_print (tkts, stdout);

    rc = shishi_tkts_to_file (tkts, outfile);
    if (rc != SHISHI_OK)
      error (EXIT_FAILURE, errno, "%s:%s", outfile, shishi_strerror (rc));

    if (!args.quiet_flag)
      {
	size_t ntkts = shishi_tkts_size (tkts);
	if (ntkts == 0)
	  printf (_("No tickets written.\n"));
	else
	  printf (ngettext ("%d ticket written.\n",
			    "%d tickets written.\n", ntkts), ntkts);
      }

    shishi_tkts_done (&tkts);
  }

  shishi_done (sh);

  return EXIT_SUCCESS;
}
