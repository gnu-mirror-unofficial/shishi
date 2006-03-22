/* shisa.c --- Command line interface to Shishi database.
 * Copyright (C) 2003, 2004, 2006  Simon Josefsson
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

/* Setup i18n. */
#ifdef HAVE_LOCALE_H
# include <locale.h>
#else
# define setlocale(Category, Locale)	/* empty */
#endif
#include <gettext.h>
#define _(String) gettext (String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

/* Get asprintf. */
#include "vasprintf.h"

/* Get xgethostname. */
#include "xgethostname.h"

/* Get set_program_name and program_name. */
#include "progname.h"

/* Get error. */
#include "error.h"

/* Shishi and Shisa library. */
#include <shisa.h>
#include <shishi.h>

/* Command line parameter parser via gengetopt. */
#include "shisa_cmd.h"

/* Global variables. */
Shishi *sh;
Shisa *dbh;
struct gengetopt_args_info args;

static void
printfield (const char *fieldname, const char *value)
{
  printf ("\t\t%s %s.\n", fieldname, value);
}

static void
printtimefield (const char *fieldname, time_t t)
{
  char *p = ctime (&t);
  p[strlen (p) - 1] = '\0';
  printfield (fieldname, t == (time_t) - 1 ? "N/A" : p);
}

static void
printintfield (const char *fieldname, int num)
{
  char *p;
  asprintf (&p, "%d (0x%x)", num, num);
  printfield (fieldname, p);
  free (p);
}

static void
printuint32field (const char *fieldname, uint32_t num)
{
  char *p;
  asprintf (&p, "%d (0x%x)", num, num);
  printfield (fieldname, p);
  free (p);
}

static void
print3field (const char *fieldname, const char *text, uint32_t num)
{
  char *p;
  asprintf (&p, "%s (0x%x, %d)", text, num, num);
  printfield (fieldname, p);
  free (p);
}

static void
printdbkey (const char *realm, const char *principal, Shisa_key * dbkey)
{
  Shishi_key *key;
  int rc;

  rc = shishi_key_from_value (sh, dbkey->etype, dbkey->key, &key);
  if (rc == SHISHI_OK)
    {
      shishi_key_realm_set (key, realm);
      shishi_key_principal_set (key, principal);
      shishi_key_print (sh, stdout, key);
    }
  else
    error (0, 0, "shishi_key_from_value failed (%d):\n%s",
	   rc, shishi_strerror (rc));
}

static int
dumplist_realm_principal (const char *realm, const char *principal)
{
  Shisa_principal ph;
  int rc;

  if (args.dump_given || args.enabled_flag || args.disabled_flag)
    {
      rc = shisa_principal_find (dbh, realm, principal, &ph);
      if (rc != SHISA_OK)
	{
	  error (0, 0, "shishi_principal_find failed (%d):\n%s",
		 rc, shisa_strerror (rc));
	  return rc;
	}

      if (args.enabled_flag && ph.isdisabled)
	return SHISA_OK;

      if (args.disabled_flag && !ph.isdisabled)
	return SHISA_OK;
    }

  printf ("\t%s\n", principal);

  if (args.dump_given)
    {
      Shisa_key **keys;
      size_t nkeys;
      size_t i;

      printfield ("Account is", ph.isdisabled ? "DISABLED" : "enabled");
      printuint32field ("Current key version", ph.kvno);
      if (ph.notusedbefore != (time_t) - 1)
	printtimefield ("Account not valid before", ph.notusedbefore);
      if (ph.lastinitialtgt != (time_t) - 1)
	printtimefield ("Last initial TGT request at", ph.lastinitialtgt);
      if (ph.lastinitialrequest != (time_t) - 1)
	printtimefield ("Last initial request at", ph.lastinitialrequest);
      if (ph.lasttgt != (time_t) - 1)
	printtimefield ("Last TGT request at", ph.lasttgt);
      if (ph.lastrenewal != (time_t) - 1)
	printtimefield ("Last ticket renewal at", ph.lastrenewal);
      if (ph.passwordexpire != (time_t) - 1)
	printtimefield ("Password expire on", ph.passwordexpire);
      if (ph.accountexpire != (time_t) - 1)
	printtimefield ("Account expire on", ph.accountexpire);

      rc = shisa_keys_find (dbh, realm, principal, NULL, &keys, &nkeys);
      if (rc != SHISA_OK)
	{
	  error (0, 0, "shishi_keys_find(%s, %s) failed (%d):\n%s",
		 realm, principal, rc, shisa_strerror (rc));
	  return rc;
	}

      for (i = 0; i < nkeys; i++)
	if (keys[i])
	  {
	    printintfield ("Key", i);

	    print3field ("\tEtype", shishi_cipher_name (keys[i]->etype),
			 keys[i]->etype);
	    if (keys[i]->priority > 0)
	      printintfield ("\tPriority", keys[i]->priority);
	    if (args.keys_given)
	      printdbkey (realm, principal, keys[i]);
	    if (keys[i]->saltlen > 0)
	      printfield ("\tSalt", keys[i]->salt);
	    if (keys[i]->str2keyparamlen > 0)
	      printfield ("\tS2K params", keys[i]->str2keyparam);
	    if (args.keys_given)
	      if (keys[i]->password)
		printfield ("\tPassword", keys[i]->password);
	  }
	else
	  printfield ("\tKey is", "MISSING");

      shisa_keys_free (dbh, keys, nkeys);
    }

  return SHISA_OK;
}

static int
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

static int
dumplist (void)
{
  int rc;

  if (args.inputs_num == 1)
    rc = dumplist_realm (args.inputs[0]);
  else if (args.inputs_num == 2)
    {
      char *realm = args.inputs[0];
      char *principal = args.inputs[1];
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

static void
add (const char *realm, const char *principal,
     Shisa_principal * ph, Shisa_key * key)
{
  int rc;

  if (principal == NULL)
    printf ("Adding realm `%s'...\n", realm);
  else
    printf ("Adding principal `%s@%s'...\n", principal, realm);

  rc = shisa_principal_add (dbh, realm, principal, ph, key);
  if (rc != SHISA_OK)
    error (EXIT_FAILURE, 0, "shisa_principal_add failed (%d):\n%s",
	   rc, shisa_strerror (rc));

  if (args.keys_given)
    printdbkey (realm, principal, key);

  if (principal == NULL)
    printf ("Adding realm `%s'...done\n", realm);
  else
    printf ("Adding principal `%s@%s'...done\n", principal, realm);
}

static void
delete (const char *realm, const char *principal)
{
  int rc;

  if (principal == NULL && args.force_flag)
    {
      char **principals;
      size_t nprincipals;
      size_t i;

      rc = shisa_enumerate_principals (dbh, realm, &principals, &nprincipals);
      if (rc != SHISA_OK)
	error (EXIT_FAILURE, 0, "shisa_enumerate_principals failed (%d):\n%s",
	       rc, shisa_strerror (rc));

      for (i = 0; i < nprincipals; i++)
	if (principals[i])
	  {
	    delete (realm, principals[i]);
	    free (principals[i]);
	  }

      if (nprincipals > 0)
	free (principals);
    }

  if (principal == NULL)
    printf ("Removing realm `%s'...\n", realm);
  else
    printf ("Removing principal `%s@%s'...\n", principal, realm);

  rc = shisa_principal_remove (dbh, realm, principal);
  if (rc != SHISA_OK)
    error (EXIT_FAILURE, 0, "shisa_principal_remove failed (%d):\n%s",
	   rc, shisa_strerror (rc));

  if (principal == NULL)
    printf ("Removing realm `%s'...done\n", realm);
  else
    printf ("Removing principal `%s@%s'...done\n", principal, realm);
}

static void
apply_options (const char *realm,
	       const char *principal, Shisa_principal * ph, Shisa_key * dbkey)
{
  char *passwd = args.password_arg;
  char *salt = args.salt_arg;
  char *str2keyparam = NULL;
  size_t str2keyparamlen = 0;
  Shishi_key *key;
  int32_t etype;
  int rc;

  if (ph)
    {
      if (args.key_version_given)
	ph->kvno = args.key_version_arg;
    }

  if (dbkey)
    {
      etype = shishi_cfg_clientkdcetype_fast (sh);

      if (args.string_to_key_parameter_given)
	{
	  /* XXX */
	}

      if (args.password_given)
	{
	  if (!passwd)
	    {
	      if (realm && principal)
		rc = shishi_prompt_password (sh, &passwd,
					     "Password for `%s@%s': ",
					     principal, realm);
	      else
		rc = shishi_prompt_password (sh, &passwd, "Password: ");
	      if (rc != SHISHI_OK)
		error (EXIT_FAILURE, 0, "Could not read password");
	    }

	  if (salt)
	    rc = shishi_key_from_string (sh, etype,
					 passwd, strlen (passwd),
					 salt, strlen (salt),
					 str2keyparam, &key);
	  else
	    {
	      char *name;
	      asprintf (&name, "%s@%s", principal, realm);

	      rc = shishi_key_from_name (sh, etype, name,
					 passwd, strlen (passwd),
					 str2keyparam, &key);
	      free (name);
	    }
	}
      else
	rc = shishi_key_random (sh, etype, &key);

      if (rc != SHISHI_OK)
	error (EXIT_FAILURE, 0, "Could not create key (%d):\n%s",
	       rc, shishi_strerror (rc));

      if (realm && principal)
	{
	  shishi_key_realm_set (key, realm);
	  shishi_key_principal_set (key, principal);
	}

      dbkey->kvno = args.key_version_arg;
      dbkey->etype = etype;
      dbkey->priority = args.priority_arg;
      dbkey->key = shishi_key_value (key);
      dbkey->keylen = shishi_key_length (key);
      dbkey->salt = salt;
      dbkey->saltlen = salt ? strlen (salt) : 0;
      dbkey->str2keyparam = str2keyparam;
      dbkey->str2keyparamlen = str2keyparamlen;
      dbkey->password = passwd;
    }
}

int
main (int argc, char *argv[])
{
  char *realm = NULL, *principal = NULL;
  Shisa_principal ph;
  Shisa_key key;
  int rc;

  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);
  set_program_name (argv[0]);

  if (cmdline_parser (argc, argv, &args) != 0)
    error (EXIT_FAILURE, 0, "Try `%s --help' for more information.",
	   program_name);

  rc = args.add_given + args.dump_given + args.list_given +
    args.modify_given + args.remove_given +
    args.key_add_given + args.key_remove_given;

  if (rc > 1 || args.inputs_num > 2)
    {
      error (0, 0, "too many arguments");
      error (EXIT_FAILURE, 0, "Try `%s --help' for more information.",
	     program_name);
    }

  if (rc == 0 || args.help_given)
    {
      cmdline_parser_print_help ();
      printf ("\nMandatory arguments to long options are "
	      "mandatory for short options too.\n\n");
      printf ("Report bugs to <%s>.\n", PACKAGE_BUGREPORT);
      return EXIT_SUCCESS;
    }

  rc = shisa_init_with_paths (&dbh, args.configuration_file_arg);
  if (rc != SHISA_OK)
    error (EXIT_FAILURE, 0, "Initialization failed:\n%s",
	   shisa_strerror (rc));

  rc = shisa_cfg (dbh, args.library_options_arg);
  if (rc != SHISA_OK)
    error (EXIT_FAILURE, 0, "Could not read library options `%s':\n%s",
	   args.library_options_arg, shisa_strerror (rc));

  rc = shishi_init (&sh);
  if (rc != SHISHI_OK)
    error (EXIT_FAILURE, 0, "Shishi initialization failed:\n%s",
	   shishi_strerror (rc));

  rc = shishi_cfg_clientkdcetype_set (sh, args.encryption_type_arg);
  if (rc != SHISHI_OK)
    error (EXIT_FAILURE, 0, "Could not set encryption type `%s':\n%s",
	   args.encryption_type_arg, shishi_strerror (rc));

  if ((args.inputs_num < 2 && (args.modify_given ||
			       args.key_add_given ||
			       args.key_remove_given)) ||
      (args.inputs_num < 1 && (args.remove_given)))
    {
      error (0, 0, "too few arguments");
      error (0, 0, "Try `%s --help' for more information.", program_name);
      return EXIT_FAILURE;
    }

  if (args.inputs_num > 0)
    realm = args.inputs[0];
  if (args.inputs_num > 1)
    principal = args.inputs[1];

  memset (&ph, 0, sizeof (ph));
  memset (&key, 0, sizeof (key));
  apply_options (realm, principal, &ph, &key);

  if (args.list_given || args.dump_given)
    rc = dumplist ();
  else if (args.remove_given)
    delete (realm, principal);
  else if (args.add_given && (args.inputs_num == 1 || args.inputs_num == 2))
    add (realm, principal, &ph, &key);
  else if (args.add_given)
    {
      char *host;
      char *tmp;
      Shisa_key key2;

      /* This is mostly meant for 'make install', as it set up the
         default realm, and write a host key to stdout, which can be
         redirected into $prefix/etc/shishi/shishi.keys. */

      realm = shishi_realm_default (sh);

      printf ("Adding default realm `%s'...\n", realm);
      add (realm, NULL, NULL, NULL);

      asprintf (&tmp, "krbtgt/%s", realm);
      add (realm, tmp, &ph, &key);
      free (tmp);

      host = xgethostname ();
      asprintf (&tmp, "host/%s", host);
      free (host);

      memset (&key2, 0, sizeof (key2));
      apply_options (realm, tmp, NULL, &key2);
      args.keys_given = 1;

      add (realm, tmp, &ph, &key2);
      free (tmp);
    }
  else if (args.modify_given)
    {
      printf ("Modifying principal `%s@%s'...\n", principal, realm);

      rc = shisa_principal_update (dbh, realm, principal, &ph);
      if (rc != SHISA_OK)
	error (EXIT_FAILURE, 0, "shisa_principal_update failed (%d):\n%s",
	       rc, shisa_strerror (rc));

      printf ("Modifying principal `%s@%s'...done\n", principal, realm);
    }
  else if (args.key_add_given)
    {
      printf ("Adding key to `%s@%s'...\n", principal, realm);

      rc = shisa_key_add (dbh, realm, principal, &key);
      if (rc != SHISA_OK)
	error (EXIT_FAILURE, 0, "shisa_key_add failed (%d):\n%s",
	       rc, shisa_strerror (rc));

      if (args.keys_given)
	printdbkey (realm, principal, &key);

      printf ("Adding key to `%s@%s'...done\n", principal, realm);
    }
  else if (args.key_remove_given)
    {
      printf ("Removing key from `%s@%s'...\n", principal, realm);

      if (!args.password_given)
	{
	  key.keylen = 0;
	  key.password = NULL;
	}

      rc = shisa_key_remove (dbh, realm, principal, &key);
      if (rc != SHISA_OK)
	error (EXIT_FAILURE, 0, "shisa_key_remove failed (%d):\n%s",
	       rc, shisa_strerror (rc));

      printf ("Removing key from `%s@%s'...done\n", principal, realm);
    }

  shisa_done (dbh);
  shishi_done (sh);

  return EXIT_SUCCESS;
}
