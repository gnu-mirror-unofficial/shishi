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
 * Realms are directories in LOCATION that contain a file called
 * "info.txt".  Principals are directories in realm directories that
 * contain a file called "info.txt".  Characters outside A-Za-z0-9_-
 * are escaped using the URL encoding, e.g. example/host%2fwww denote
 * the "host/www" principal in the "example" realm.
 *
 * Example file tree:
 *
 * LOCATION/EXAMPLE.ORG
 * LOCATION/EXAMPLE.ORG/info.txt
 * LOCATION/EXAMPLE.ORG/krbtgt%2fEXAMPLE.ORG
 * LOCATION/EXAMPLE.ORG/krbtgt%2fEXAMPLE.ORG/info.txt
 * LOCATION/EXAMPLE.ORG/host%2fkerberos.example.org
 * LOCATION/EXAMPLE.ORG/host%2fkerberos.example.org/info.txt
 *
 */

#include "internal.h"

/* For stat. */
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* For readdir. */
#include <dirent.h>

#include <errno.h>
#ifndef errno
extern int errno;
#endif

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
  struct stat buf;
  int rc;

  rc = stat (location, &buf);
  if (rc != 0 || !S_ISDIR (buf.st_mode))
    {
      errno = ENOTDIR;
      perror (location);
      return SHISA_DB_OPEN_ERROR;
    }

  *state = info = xcalloc (1, sizeof (*info));
  rc = shisa_file_cfg (dbh, info, options);
  if (rc != SHISA_OK)
    return rc;

  info->path = xstrdup (location);

  return SHISA_OK;
}

static int
has_info_txt (char *path, char *directory)
{
  struct stat buf;
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s/info.txt", path, directory);

  rc = stat (tmp, &buf);

  free (tmp);

  if (rc != 0 || !S_ISREG (buf.st_mode))
    return 0;

  return 1;
}

static int
shisa_file_ls_1 (Shisa *dbh,
		 char *path,
		 char ***files,
		 size_t *nfiles,
		 DIR *dir)
{
  struct dirent *de;
  int rc;

  while (errno = 0, (de = readdir (dir)) != NULL)
    {
      if (strcmp (de->d_name, ".") == 0 || strcmp (de->d_name, "..") == 0)
	continue;
      if (has_info_txt (path, de->d_name))
	{
	  *files = xrealloc (*files, (*nfiles + 1) * sizeof (**files));
	  (*files)[(*nfiles)++] = xstrdup (de->d_name);
	}
    }

  if (errno != 0)
    {
      size_t i;

      perror(path);

      for (i = 0; i < *nfiles; i++)
	free (**files);
      free (*files);

      return SHISA_DB_LIST_REALM_ERROR;
    }

  return SHISA_OK;
}

static int
shisa_file_ls (Shisa *dbh,
	       char *path,
	       char ***files,
	       size_t *nfiles)
{
  struct dirent *de;
  DIR *dir;
  int rc, tmprc;

  dir = opendir (path);
  if (dir == NULL)
    {
      perror(path);
      return SHISA_DB_LIST_REALM_ERROR;
    }

  rc = shisa_file_ls_1 (dbh, path, files, nfiles, dir);
  if (rc != SHISA_OK)
    {
      rc = closedir (dir);
      if (rc != 0)
	perror (path);
      return SHISA_DB_LIST_REALM_ERROR;
    }

  rc = closedir (dir);
  if (rc != 0)
    {
      size_t i;

      perror(path);

      for (i = 0; i < *nfiles; i++)
	free (**files);
      free (*files);

      return SHISA_DB_LIST_REALM_ERROR;
    }

  return SHISA_OK;
}


extern int
shisa_file_enumerate_realms (Shisa *dbh,
			     void *state,
			     char ***realms,
			     size_t *nrealms)
{
  Shisa_file *info = state;
  int rc;

  rc = shisa_file_ls (dbh, info->path, realms, nrealms);

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
  char *tmp;
  int rc;

  asprintf (&tmp, "%s/%s", info->path, realm);

  rc = shisa_file_ls (dbh, tmp, principals, nprincipals);

  free (tmp);

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

  return SHISA_INIT_ERROR;
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
