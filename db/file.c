/* file.c --- File based Kerberos database.
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

/*
 * Theory of operation:
 *
 * Data is stored in the standard file system, so it is subject to
 * normal access permission infrastructure, e.g. POSIX ACL or normal
 * Unix file permissions.  A definition of the file database looks
 * like:
 *
 * file LOCATION OPTIONS
 *
 * Where LOCATION is a path name, e.g. /var/shisa.  No OPTIONS are
 * currently implemented.
 *
 * Realms are directories in LOCATION.  Principals are directories in
 * realm directories.  Characters outside A-Za-z0-9_- are escaped
 * using the URL encoding, e.g. example/host%2fwww denote the
 * "host/www" principal in the "example" realm.
 *
 * Example file tree:
 *
 * LOCATION/EXAMPLE.ORG
 * LOCATION/EXAMPLE.ORG/krbtgt%2fEXAMPLE.ORG
 * LOCATION/EXAMPLE.ORG/host%2fkerberos.example.org
 * LOCATION/EXAMPLE.NET
 * LOCATION/EXAMPLE.NET/krbtgt%2fEXAMPLE.NET
 *
 */

#include "internal.h"

/* fileutil.c */
extern int _shisa_isdir (const char *path);
extern int _shisa_isdir3 (const char *path1, const char *path2,
			  const char *path3);
extern int _shisa_mtime4 (const char *path1, const char *path2,
			  const char *path3, const char *path4);
extern int _shisa_isfile4 (const char *path1, const char *path2,
			   const char *path3, const char *path4);
extern int _shisa_uint32link4 (const char *path1, const char *path2,
			       const char *path3, const char *path4);
extern int _shisa_ls (const char *path, char ***files, size_t *nfiles);
extern int _shisa_ls2 (const char *path1, const char *path2,
		       char ***files, size_t *nfiels);

struct Shisa_file
{
  char *path;
  int readonly;
  int allowcreate;
};
typedef struct Shisa_file Shisa_file;

enum
  {
    READ_ONLY_OPTION = 0,
    ALLOW_CREATE_OPTION = 1,
    THE_END
  };

static char *const _shisa_file_opts[] = {
  /* [READ_ONLY_OPTION] =        */ "read-only",
  /* [ALLOW_CREATE_OPTION] =     */ "allow-create",
  /* [THE_END] =                 */ NULL
};

int
shisa_file_cfg (Shisa *dbh,
		Shisa_file *info,
		const char *option)
{
  char *opt = option ? xstrdup (option) : NULL;
  char *p = opt;
  char *value;
  int rc;

  while (p != NULL && *p != '\0')
    {
      switch (getsubopt (&p, _shisa_file_opts, &value))
	{
	case READ_ONLY_OPTION:
	  info->readonly = 1;
	  break;

	case ALLOW_CREATE_OPTION:
	  info->allowcreate = 1;
	  break;

	default:
	  shisa_info (dbh, "Unknown file database option: `%s'.", value);
	  return SHISA_CFG_SYNTAX_ERROR;
	  break;
	}
    }

  if (opt)
    free (opt);

  return SHISA_OK;
}

int
shisa_file_init (Shisa *dbh,
		 const char *location,
		 const char *options,
		 void **state)
{
  Shisa_file *info;
  int rc;

  if (!_shisa_isdir (location))
    return SHISA_OPEN_ERROR;

  *state = info = xcalloc (1, sizeof (*info));
  rc = shisa_file_cfg (dbh, info, options);
  if (rc != SHISA_OK)
    return rc;

  info->path = xstrdup (location);

  return SHISA_OK;
}

int
shisa_file_enumerate_realms (Shisa *dbh,
			     void *state,
			     char ***realms,
			     size_t *nrealms)
{
  Shisa_file *info = state;
  int rc;

  rc = _shisa_ls (info->path, realms, nrealms);

  return rc;
}

int
shisa_file_enumerate_principals (Shisa *dbh,
				 void *state,
				 const char *realm,
				 char ***principals,
				 size_t *nprincipals)
{
  Shisa_file *info = state;
  int rc;

  rc = _shisa_ls2 (info->path, realm, principals, nprincipals);

  return rc;
}

int
shisa_file_principal_find (Shisa * dbh,
			   void *state,
			   const char *client,
			   const char *realm,
			   Shisa_principal **ph)
{
  Shisa_file *info = state;
  Shisa_principal *princ;

  if (!_shisa_isdir3 (info->path, realm, client))
    return SHISA_NO_PRINCIPAL;

  princ = xmalloc (sizeof (*princ));
  princ->name = xstrdup (client);
  princ->realm = xstrdup (realm);
  princ->notusedbefore =
    _shisa_mtime4 (info->path, realm, client, "validfrom.stamp");
  princ->isdisabled =
    _shisa_isfile4 (info->path, realm, client, "disabled.flag");
  princ->kvno = _shisa_uint32link4 (info->path, realm, client, "latest.key");
  princ->lastinitialtgt =
    _shisa_mtime4 (info->path, realm, client, "lastinitaltgt.stamp");
  princ->lastinitialrequest =
    _shisa_mtime4 (info->path, realm, client, "lastinitial.stamp");
  princ->lasttgt = _shisa_mtime4 (info->path, realm, client, "lasttgt.stamp");
  princ->lastrenewal =
    _shisa_mtime4 (info->path, realm, client, "lastrenewal.stamp");
  princ->passwordexpire =
    _shisa_mtime4 (info->path, realm, client, "passwordexpire.stamp");
  princ->accountexpire =
    _shisa_mtime4 (info->path, realm, client, "accountexpire.stamp");

  *ph = princ;

  return SHISA_OK;
}

void
shisa_file_done (Shisa *dbh, void *state)
{
  Shisa_file *info = state;

  if (info)
    {
      if (info->path)
	free (info->path);
      free (info);
    }
}
