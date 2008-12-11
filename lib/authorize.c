/* authorize.c --- Authorization to services of authenticated principals.
 * Copyright (C) 2003, 2004, 2006, 2007, 2008  Simon Josefsson
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

#ifdef HAVE_PWD_H
# include <pwd.h>
#endif

int
shishi_authorize_strcmp (Shishi * handle, const char *principal,
			 const char *authzname)
{
  if (strcmp (principal, authzname) == 0)
    return 1;

  return 0;
}

/* MIT/Heimdal authorization method */
int
shishi_authorize_k5login (Shishi * handle, const char *principal,
			  const char *authzname)
{
#if HAVE_PWD_H && HAVE_GETPWNAM
  struct passwd *pwd;
  struct stat sta;
  FILE *fic;
  char *ficname;
  char *line = NULL;
  size_t linelength = 0;
  int authorized = 0;

  pwd = getpwnam (authzname);
  if (pwd == NULL || pwd->pw_dir == NULL)
    return 0;

  asprintf (&ficname, "%s%s", pwd->pw_dir, ".k5login");

  if (stat (ficname, &sta) != 0)
    /* If file .k5login does not exist */
    if (strcmp (principal, authzname) == 0)
      return shishi_authorize_strcmp (handle, principal, authzname);

  /* Owner should be user or root */
  if ((sta.st_uid != pwd->pw_uid) && (sta.st_uid != 0))
    {
      free (ficname);
      return 0;
    }

  fic = fopen (ficname, "r");
  if (fic == NULL)
    {
      free (ficname);
      return 0;
    }

  while (!feof (fic))
    {
      if (getline (&line, &linelength, fic) == -1)
	break;
      line[linelength - 1] = '\0';

      if (strcmp (principal, line) == 0)
	{
	  authorized = 1;
	  break;
	}
    }

  fclose (fic);
  free (ficname);
  free (line);

  return authorized;
#else
  return 0;
#endif
}

struct Authorization_aliases
{
  const char *name;
  int type;
};

static const struct Authorization_aliases authorization_aliases[] = {
  {"basic", SHISHI_AUTHORIZATION_BASIC},
  {"k5login", SHISHI_AUTHORIZATION_K5LOGIN}
};

/**
 * shishi_authorization_parse:
 * @authorization: name of authorization type, e.g. "basic".
 *
 * Parse authorization type name.
 *
 * Return value: Return authorization type corresponding to a string.
 **/
int
shishi_authorization_parse (const char *authorization)
{
  size_t i;
  char *endptr;

  i = strtol (authorization, &endptr, 0);

  if (endptr != authorization)
    return i;

  for (i = 0;
       i < sizeof (authorization_aliases) / sizeof (authorization_aliases[0]);
       i++)
    if (strcasecmp (authorization, authorization_aliases[i].name) == 0)
      return authorization_aliases[i].type;

  return -1;
}

/**
 * shishi_authorized_p:
 * @handle: shishi handle as allocated by shishi_init().
 * @tkt: input variable with ticket info.
 * @authzname: authorization name.
 *
 * Simplistic authorization of @authzname against encrypted client
 * principal name inside ticket.  Currently this function only compare
 * the principal name with @authzname using strcmp().
 *
 * Return value: Returns 1 if authzname is authorized for services by
 *   authenticated client principal, or 0 otherwise.
 **/
int
shishi_authorized_p (Shishi * handle, Shishi_tkt * tkt, const char *authzname)
{
  char *client;
  size_t i;
  int rc;

  rc = shishi_encticketpart_client (handle, shishi_tkt_encticketpart (tkt),
				    &client, NULL);
  if (rc != SHISHI_OK)
    return 0;

  for (i = 0; i < handle->nauthorizationtypes; i++)
    {
      switch (handle->authorizationtypes[i])
	{
	case SHISHI_AUTHORIZATION_BASIC:
	  if (shishi_authorize_strcmp (handle, client, authzname))
	    return 1;
	  break;

	case SHISHI_AUTHORIZATION_K5LOGIN:
	  if (shishi_authorize_k5login (handle, client, authzname))
	    return 1;
	  break;

	default:
	  return 0;
	}
    }

  return 0;
}
