/* shisa.c --- Command line interface to Shishi database.
 * Copyright (C) 2003  Simon Josefsson
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
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>

#ifdef HAVE_LOCALE_H
# include <locale.h>
#else
# define setlocale(Category, Locale) /* empty */
#endif

#include <gettext.h>
#define _(String) gettext (String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

#include <shisa.h>

#include "shisa_cmd.h"

int
main (int argc, char *argv[])
{
  Shisa *dbh;
  struct gengetopt_args_info args_info;
  int rc;

  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  if (cmdline_parser (argc, argv, &args_info) != 0)
    return 1;

  rc = shisa_init_with_paths (&dbh, args_info.configuration_file_arg);
  if (rc != SHISA_OK)
    error (1, 0, "Initialization failed: %s", shisa_strerror (rc));

  rc = shisa_cfg (dbh, args_info.library_options_arg);
  if (rc != SHISA_OK)
    error (1, 0, "Could not read library options `%s': %s",
	   args_info.library_options_arg, shisa_strerror (rc));

  shisa_done (dbh);

  return 0;
}
