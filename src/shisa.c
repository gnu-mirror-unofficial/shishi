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
#include <shishi.h>

#include "shisa_cmd.h"

/* The name the program was run with, stripped of any leading path. */
char *program_name;

Shishi *sh;
Shisa *dbh;
struct gengetopt_args_info args_info;

void
printfield (const char *fieldname, const char *value)
{
  printf ("\t\t%s %s.\n", fieldname, value);
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
dumplist_realm_principal (const char *realm, const char *principal)
{
  Shisa_principal ph;
  int rc;

  if (args_info.dump_given ||
      args_info.enabled_flag ||
      args_info.disabled_flag)
    {
      rc = shisa_principal_find (dbh, realm, principal, &ph);
      if (rc != SHISA_OK)
	return rc;
    }

  if (args_info.enabled_flag && ph.isdisabled)
    return SHISA_OK;

  if (args_info.disabled_flag && !ph.isdisabled)
    return SHISA_OK;

  printf("\t%s\n", principal);

  if (args_info.dump_given)
    {
      printfield ("Account is", ph.isdisabled ? "DISABLED" : "enabled");
      printuint32field ("Current key version", ph.kvno);
      if (ph.notusedbefore != (time_t) -1)
	printtimefield ("Account not valid before", ph.notusedbefore);
      if (ph.lastinitialtgt != (time_t) -1)
	printtimefield ("Last initial TGT request at", ph.lastinitialtgt);
      if (ph.lastinitialrequest != (time_t) -1)
	printtimefield ("Last initial request at", ph.lastinitialrequest);
      if (ph.lasttgt != (time_t) -1)
	printtimefield ("Last TGT request at", ph.lasttgt);
      if (ph.lastrenewal != (time_t) -1)
	printtimefield ("Last ticket renewal at", ph.lastrenewal);
      if (ph. passwordexpire!= (time_t) -1)
	printtimefield ("Password expire on", ph.passwordexpire);
      if (ph.accountexpire != (time_t) -1)
	printtimefield ("Account expire on", ph.accountexpire);
    }

  if (args_info.keys_given)
    {
      Shisa_key **keys;
      size_t nkeys;
      size_t i;

      printf ("\t\tKeys:\n");

      rc = shisa_enumerate_keys (dbh, realm, principal, &keys, &nkeys);
      if (rc == SHISA_OK)
	{
	  for (i = 0; i < nkeys; i++)
	    {
	      if (keys[i])
		{
		  printuint32field ("\tEtype", keys[i]->etype);
		  printfield ("\tKey", keys[i]->key);
		  printfield ("\tSalt", keys[i]->salt);
		  printfield ("\tS2K params", keys[i]->str2keyparam);
		  printfield ("\tPassword", keys[i]->password);
		  shisa_key_free (dbh, keys[i]);
		}
	      else
		printfield ("\tKey is", "MISSING");
	    }
	  if (nkeys > 0)
	    free (keys);
	}
    }

  return SHISA_OK;
}

int
dumplist_realm (const char *realm)
{
  char **principals;
  size_t nprincipals;
  size_t i;
  int rc;

  printf ("%s\n", realm);

  rc = shisa_enumerate_principals (dbh, realm, &principals, &nprincipals);
  if (rc != SHISA_OK)
    return rc;

  for (i = 0; i < nprincipals; i++)
    {
      if (rc == SHISA_OK)
	rc = dumplist_realm_principal (realm, principals[i]);
      free (principals[i]);
    }
  if (nprincipals > 0)
    free (principals);

  return rc;
}

int
dumplist (void)
{
  int rc;

  if (args_info.inputs_num == 1)
    rc = dumplist_realm (args_info.inputs[0]);
  else if (args_info.inputs_num == 2)
    {
      char *realm = args_info.inputs[0];
      char *principal = args_info.inputs[1];
      printf ("%s\n", realm);
      rc = dumplist_realm_principal (realm, principal);
    }
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
	    rc = dumplist_realm (realms[i]);
	  free (realms[i]);
	}
      if (nrealms > 0)
	free (realms);
    }

  return rc;
}

int
apply_options (const char *realm,
	       const char *principal,
	       Shisa_principal *ph,
	       Shisa_key *dbkey)
{
  char *passwd = args_info.password_arg;
  char *salt = args_info.salt_arg;
  char *str2keyparam = NULL;
  size_t str2keyparamlen = 0;
  Shishi_key *key;
  int32_t etype;
  int rc;

  if (args_info.encryption_type_given)
    {
      rc = shishi_cfg_clientkdcetype_set (sh, args_info.encryption_type_arg);
      if (rc != SHISHI_OK)
	return EXIT_FAILURE;
    }
  etype = shishi_cfg_clientkdcetype_fast (sh);

  if (salt == NULL)
    asprintf (&salt, "%s%s", realm, principal);

  if (args_info.string_to_key_parameter_given)
    {
      /* XXX */
    }

  if (args_info.password_given)
    {
      if (!passwd)
	{
	  rc = shishi_prompt_password (sh, &passwd, "Password for `%s@%s': ",
				       principal, realm);
	  if (rc != SHISHI_OK)
	    return EXIT_FAILURE;
	}

      rc = shishi_key_from_string (sh, etype,
				   passwd, strlen (passwd),
				   salt, strlen (salt),
				   str2keyparam,
				   &key);
    }
  else
    rc = shishi_key_random (sh, etype, &key);
  if (rc != SHISHI_OK)
    return EXIT_FAILURE;

  if (!args_info.quiet_flag)
    shishi_key_print (sh, stdout, key);

  dbkey->etype = etype;
  dbkey->key = shishi_key_value (key);
  dbkey->keylen = shishi_key_length (key);
  dbkey->salt = salt;
  dbkey->saltlen = strlen (salt);
  dbkey->str2keyparam = str2keyparam;
  dbkey->str2keyparamlen = str2keyparamlen;
  dbkey->password = passwd;

  return EXIT_SUCCESS;
}

int
modify_principal (const char *realm, const char *principal)
{
  Shisa_principal ph;
  int rc;

  printf ("Modifying principal `%s@%s'...\n", principal, realm);

  rc = shisa_principal_update (dbh, realm, principal, &ph);
  if (rc != SHISA_OK)
    {
      printf ("failure: %s\n", shisa_strerror (rc));
      return EXIT_FAILURE;
    }

  printf ("Modifying principal `%s@%s'...done\n", principal, realm);

  return EXIT_SUCCESS;
}

int
modify (void)
{
  int rc;

  if (args_info.inputs_num == 2)
    rc = modify_principal (args_info.inputs[0], args_info.inputs[1]);
  else
    {
      error (0, 0, "too few arguments");
      error (0, 0, "Try `%s --help' for more information.", program_name);
      return EXIT_FAILURE;
    }

  return EXIT_SUCCESS;
}

int
add_principal (const char *realm, const char *principal)
{
  Shisa_principal ph;
  Shisa_key key;
  int rc;

  memset (&ph, 0, sizeof(ph));
  memset (&key, 0, sizeof(key));
  rc = apply_options (realm, principal, &ph, &key);
  if (rc != EXIT_SUCCESS)
    return EXIT_FAILURE;

  if (principal == NULL)
    printf ("Adding realm `%s'...\n", realm);
  else
    printf ("Adding principal `%s@%s'...\n", principal, realm);

  rc = shisa_principal_add (dbh, realm, principal, &ph, &key);
  if (rc != SHISA_OK)
    {
      printf ("failure: %s\n", shisa_strerror (rc));
      return EXIT_FAILURE;
    }

  if (principal == NULL)
    printf ("Adding realm `%s'...done\n", realm);
  else
    printf ("Adding principal `%s@%s'...done\n", principal, realm);

  return EXIT_SUCCESS;
}

int
add (void)
{
  int rc;

  if (args_info.inputs_num == 1)
    rc = add_principal (args_info.inputs[0], NULL);
  else if (args_info.inputs_num == 2)
    rc = add_principal (args_info.inputs[0], args_info.inputs[1]);
  else
    {
      error (0, 0, "too few arguments");
      error (0, 0, "Try `%s --help' for more information.", program_name);
      return EXIT_FAILURE;
    }

  return EXIT_SUCCESS;
}

int
delete_principal (const char *realm, const char *principal)
{
  int rc;

  if (principal == NULL && args_info.force_flag)
    {
      char **principals;
      size_t nprincipals;
      size_t i;

      rc = shisa_enumerate_principals (dbh, realm, &principals, &nprincipals);
      if (rc != SHISA_OK)
	return rc;

      for (i = 0; i < nprincipals; i++)
	{
	  if (rc == SHISA_OK)
	    rc = delete_principal (realm, principals[i]);
	  free (principals[i]);
	}
      if (nprincipals > 0)
	free (principals);

      if (rc != SHISA_OK)
	return rc;
    }

  if (principal == NULL)
    printf ("Removing realm `%s'...\n", realm);
  else
    printf ("Removing principal `%s@%s'...\n", principal, realm);

  rc = shisa_principal_remove (dbh, realm, principal);
  if (rc != SHISA_OK)
    {
      printf ("failure: %s\n", shisa_strerror (rc));
      return EXIT_FAILURE;
    }

  if (principal == NULL)
    printf ("Removing realm `%s'...done\n", realm);
  else
    printf ("Removing principal `%s@%s'...done\n", principal, realm);

  return EXIT_SUCCESS;
}

int
delete (void)
{
  int rc;

  if (args_info.inputs_num == 1)
    rc = delete_principal (args_info.inputs[0], NULL);
  else if (args_info.inputs_num == 2)
    rc = delete_principal (args_info.inputs[0], args_info.inputs[1]);
  else
    {
      error (0, 0, "too few arguments");
      error (0, 0, "Try `%s --help' for more information.", program_name);
      return EXIT_FAILURE;
    }

  return EXIT_SUCCESS;
}

int
main (int argc, char *argv[])
{
  int rc;

  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);
  program_name = argv[0];

  if (cmdline_parser (argc, argv, &args_info) != 0)
    {
      error (1, 0, "Try `%s --help' for more information.", argv[0]);
      return 1;
    }

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
      printf("\nMandatory arguments to long options are "
	     "mandatory for short options too.\n\n"
	     "Report bugs to <%s>.\n", PACKAGE_BUGREPORT);
      return 1;
    }

  puts ("WARNING: The on-disk database format is not stable.");
  puts ("WARNING: It will likely change in the next release.");
  puts ("WARNING: The old format will not be recognized.");
  puts ("");

  rc = shisa_init_with_paths (&dbh, args_info.configuration_file_arg);
  if (rc != SHISA_OK)
    error (1, 0, "Initialization failed:\n%s", shisa_strerror (rc));

  rc = shisa_cfg (dbh, args_info.library_options_arg);
  if (rc != SHISA_OK)
    error (1, 0, "Could not read library options `%s':\n%s",
	   args_info.library_options_arg, shisa_strerror (rc));

  rc = shishi_init (&sh);
  if (rc != SHISHI_OK)
    error (1, 0, "Shishi initialization failed:\n%s", shishi_strerror (rc));

  if (args_info.encryption_type_given)
    {
      rc = shishi_cfg_clientkdcetype_set (sh, args_info.encryption_type_arg);
      if (rc != SHISHI_OK)
	error (1, 0, "Could not set encryption type `%s':\n%s",
	       args_info.encryption_type_arg, shishi_strerror (rc));
    }

  if (args_info.list_given || args_info.dump_given)
    rc = dumplist ();
  else if (args_info.add_given)
    rc = add ();
  else if (args_info.remove_given)
    rc = delete ();
  else if (args_info.modify_given)
    rc = modify ();

  shisa_done (dbh);
  shishi_done (sh);

  return rc;
}
