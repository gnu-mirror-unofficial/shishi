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

void
printfield (const char *fieldname, const char *value)
{
  printf ("\t%s %s.\n", fieldname, value);
}

void
printtimefield (const char *fieldname, time_t t)
{
  char *p = ctime (&t);
  p[strlen(p) - 1] = '\0';
  printfield (fieldname, t == (time_t) -1 ? "N/A" : p);
}

void
printuint32field (const char *fieldname, uint32_t num)
{
  char *p;
  asprintf (&p, "%d (0x%x)", num, num);
  printfield (fieldname, p);
  free (p);
}

int
dumplist_realm_principal (Shisa *dbh,
			  struct gengetopt_args_info args_info,
			  const char *realm,
			  const char *principal)
{
  Shisa_principal *ph = NULL;
  int rc;

  if (args_info.dump_given ||
      args_info.enabled_flag ||
      args_info.disabled_flag)
    {
      rc = shisa_principal_find (dbh, principal, realm, &ph);
      if (rc != SHISA_OK)
	return rc;
    }

  if (args_info.enabled_flag && ph->isdisabled)
    return SHISA_OK;

  if (args_info.disabled_flag && !ph->isdisabled)
    return SHISA_OK;

  printf("%s@%s\n", principal, realm);

  if (args_info.dump_given)
    {
      printfield ("Account is", ph->isdisabled ? "DISABLED" : "enabled");
      printuint32field ("Current key version", ph->kvno);
      if (ph->notusedbefore != (time_t) -1)
	printtimefield ("Account not valid before", ph->notusedbefore);
      if (ph->lastinitialtgt != (time_t) -1)
	printtimefield ("Last initial TGT request at", ph->lastinitialtgt);
      if (ph->lastinitialrequest != (time_t) -1)
	printtimefield ("Last initial request at", ph->lastinitialrequest);
      if (ph->lasttgt != (time_t) -1)
	printtimefield ("Last TGT request at", ph->lasttgt);
      if (ph->lastrenewal != (time_t) -1)
	printtimefield ("Last ticket renewal at", ph->lastrenewal);
      if (ph-> passwordexpire!= (time_t) -1)
	printtimefield ("Password expire on", ph->passwordexpire);
      if (ph->accountexpire != (time_t) -1)
	printtimefield ("Account expire on", ph->accountexpire);
    }

  if (ph != NULL)
    shisa_principal_free (ph);

  return SHISA_OK;
}

int
dumplist_realm (Shisa *dbh, struct gengetopt_args_info args_info,
		const char *realm)
{
  char **principals;
  size_t nprincipals;
  size_t i;
  int rc;

  rc = shisa_enumerate_principals (dbh, realm, &principals, &nprincipals);
  if (rc != SHISA_OK)
    return rc;

  for (i = 0; i < nprincipals; i++)
    {
      if (rc == SHISA_OK)
	rc = dumplist_realm_principal (dbh, args_info, realm, principals[i]);
      free (principals[i]);
    }
  free (principals);

  return rc;
}

int
dumplist (Shisa *dbh, struct gengetopt_args_info args_info)
{
  int rc;

  if (args_info.inputs_num == 1)
    rc = dumplist_realm (dbh, args_info, args_info.inputs[0]);
  else if (args_info.inputs_num == 2)
    rc = dumplist_realm_principal (dbh, args_info, args_info.inputs[0],
				   args_info.inputs[1]);
  else
    {
      char **realms;
      size_t nrealms;
      size_t i;

      rc = shisa_enumerate_realms (dbh, &realms, &nrealms);
      if (rc != SHISA_OK)
	return rc;

      for (i = 0; i < nrealms; i++)
	{
	  if (rc == SHISA_OK)
	    rc = dumplist_realm (dbh, args_info, realms[i]);
	  free (realms[i]);
	}
      free (realms);
    }

  return rc;
}

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

  if (args_info.add_given + args_info.dump_given + args_info.list_given +
      args_info.modify_given + args_info.remove_given > 1 ||
      args_info.inputs_num > 2)
    {
      error (0, 0, "too many arguments");
      error (1, 0, "Try `%s --help' for more information.", argv[0]);
    }

  if (args_info.add_given + args_info.dump_given + args_info.list_given +
      args_info.modify_given + args_info.remove_given != 1)
    {
      cmdline_parser_print_help ();
      return 1;
    }

  rc = shisa_init_with_paths (&dbh, args_info.configuration_file_arg);
  if (rc != SHISA_OK)
    error (1, 0, "Initialization failed: %s", shisa_strerror (rc));

  rc = shisa_cfg (dbh, args_info.library_options_arg);
  if (rc != SHISA_OK)
    error (1, 0, "Could not read library options `%s': %s",
	   args_info.library_options_arg, shisa_strerror (rc));

  if (args_info.list_given || args_info.dump_given)
    {
      rc = dumplist (dbh, args_info);
      if (rc != SHISA_OK)
	error (0, 0, "List failed: %s", shisa_strerror (rc));
    }
  else
    rc = 1;

  shisa_done (dbh);

  return rc;
}
