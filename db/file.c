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

#include "internal.h"

struct Shisa_file
{
  char *path;
  FILE *fh;
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
  FILE *fh;
  int rc;

  *state = info = xcalloc (1, sizeof (*info));
  rc = shisa_file_cfg (dbh, info, options);
  if (rc != SHISA_OK)
    return rc;

  if (info->readonly)
    info->fh = fopen (location, "r");
  else
    info->fh = fopen (location, "r+");
  if (info->fh == NULL && info->allowcreate)
    {
      info->fh = fopen (location, "w+");
      if (info->fh != NULL)
	shisa_info (dbh, "Created file database: `%s'.", location);
    }
  if (info->fh == NULL)
    {
      free (info);
      perror(location);
      return SHISA_DB_OPEN_ERROR;
    }

  info->path = xstrdup (location);

  return SHISA_OK;
}

void
shisa_file_done (Shisa *dbh, void *state)
{
  Shisa_file *info = state;

  if (!info)
    return;

  if (info->fh)
    if (fclose (info->fh) != 0)
      perror(info->path);
  if (info->path)
    free (info->path);
  free (info);
}
