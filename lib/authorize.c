/* authorize.c	Authorization to services of authenticated Kerberos principals.
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

#include "internal.h"

int
shishi_authorize_strcmp (Shishi * handle, const char *principal,
			 const char *authzname)
{
  if (strcmp (principal, authzname) == 0)
    return 1;

  return 0;
}

/* MIT/Heimdal kerberos 5 authorization method */
int
shishi_authorize_k5login (Shishi * handle, const char *principal,
			  const char *authzname)
{
  struct passwd *pwd;
  struct stat sta;
  FILE *fic;
  char *ficname;
  char *line = NULL;
  size_t linelength = 0;
  int authorized = 0;

  pwd = getpwnam (authzname);
  if (pwd == NULL)
    return authorized;

  asprintf (&ficname, "%s%s", pwd->pw_dir, ".k5login");

  if (stat (ficname, &sta) != 0)
    /* If file .k5login does not exist */
    if (strcmp (principal, authzname) == 0)
      return shishi_authorize_strcmp (handle, principal, authzname);

  /* Owner should be user or root */
  if ((sta.st_uid != pwd->pw_uid) && (sta.st_uid != 0))
    {
      free (pwd);
      free (ficname);
      return authorized;
    }

  fic = fopen (ficname, "r");
  if (fic == NULL)
    {
      free (pwd);
      free (ficname);
      return authorized;
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
  free (pwd);
  free (ficname);
  free (line);

  return authorized;
}

static struct
{
  char *name;
  int type;
} authorization_aliases[] =
{
  {
  "basic", SHISHI_AUTHORIZATION_BASIC},
  {
  "k5login", SHISHI_AUTHORIZATION_K5LOGIN}
};

/**
 * shishi_authorization_parse:
 * @authorization: name of authorization type, e.g. "basic".
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
 *   authenticated Kerberos client principal, or 0 otherwise.
 **/
int
shishi_authorized_p (Shishi * handle, Shishi_tkt * tkt, const char *authzname)
{
  char cname[BUFSIZ];		/* XXX */
  size_t cnamelen = sizeof (cname);
  int rc;
  int i;

  rc = shishi_encticketpart_cname_get (handle,
				       shishi_tkt_encticketpart (tkt),
				       cname, &cnamelen);
  if (rc != SHISHI_OK)
    return 0;

  for (i = 0; i < handle->nauthorizationtypes; i++)
    {
      switch (handle->authorizationtypes[i])
	{
	case SHISHI_AUTHORIZATION_BASIC:
	  if (shishi_authorize_strcmp (handle, cname, authzname))
	    return 1;
	  break;

	case SHISHI_AUTHORIZATION_K5LOGIN:
	  if (shishi_authorize_k5login (handle, cname, authzname))
	    return 1;
	  break;
	}
    }

  return 0;
}