/* cfg.c --- Read Shisa Configuration file.
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

enum
{
  DB_OPTION = 0,
  THE_END
};

static char *const _shisa_opts[] = {
  /* [DB_OPTION] =        */ "db",
  /* [THE_END] =          */ NULL
};

/**
 * shisa_cfg_db:
 * @handle: Shisa library handle created by shishi().
 * @value: string with database definition.
 *
 * Setup and open a new database.  The syntax of the @value parameter
 * is "TYPE[ LOCATION[ PARAMETER]]", where TYPE is one of the
 * supported database types (e.g., "file") and LOCATION and PARAMETER
 * are optional strings passed to the database during initialization.
 * Neither TYPE nor LOCATION can contain " " (SPC), but PARAMETER may.
 *
 * Return Value: Returns %SHISA_OK if database was parsed and open
 *   successfully.
 **/
int
shisa_cfg_db (Shisa * dbh, char *value)
{
  char *p;
  char *db;
  char *location = NULL;
  char *options = NULL;
  _Shisa_backend *backend;
  void *state;
  int rc;

  db = xstrdup (value);
  if ((p = strchr (db, ' ')))
    {
      *p++ = '\0';
      location = p;
      if ((p = strchr (p, ' ')))
	{
	  *p++ = '\0';
	  options = p;
	}
    }

  backend = _shisa_find_backend (db);
  if (backend == NULL)
    {
      fprintf (stderr, "Unknown database type: `%s'\n", db);
      return SHISA_CFG_ERROR;
    }

  rc = backend->init (dbh, location, options, &state);
  if (rc != SHISA_OK)
    {
      fprintf (stderr, "Cannot initialize `%s' database backend\n", db);
      return rc;
    }

  dbh->dbs = xrealloc (dbh->dbs, ++dbh->ndbs * sizeof (*dbh->dbs));
  dbh->dbs->backend = backend;
  dbh->dbs->state = state;

  return SHISA_OK;
}

/**
 * shisa_cfg:
 * @handle: Shisa library handle created by shishi().
 * @option: string with shisa library option.
 *
 * Configure shisa library with given option.
 *
 * Return Value: Returns SHISA_OK if option was valid.
 **/
int
shisa_cfg (Shisa * dbh, char *option)
{
  char *value;
  int rc;

  while (option != NULL && *option != '\0')
    {
      switch (getsubopt (&option, _shisa_opts, &value))
	{
	case DB_OPTION:
	  rc = shisa_cfg_db (dbh, value);
	  if (rc != SHISA_OK)
	    return rc;
	  break;

	default:
	  fprintf (stderr, "Unknown option: `%s'", value);
	  break;
	}
    }

  return SHISA_OK;
}

/**
 * shisa_cfg_from_file:
 * @handle: Shishi library handle create by shishi_init().
 * @cfg: filename to read configuration from.
 *
 * Configure shishi library using configuration file.
 *
 * Return Value: Returns SHISHI_OK iff succesful.
 **/
int
shisa_cfg_from_file (Shisa * dbh, const char *cfg)
{
  struct linebuffer lb;
  FILE *fh;

  if (cfg == NULL)
    return SHISA_OK;

  fh = fopen (cfg, "r");
  if (fh == NULL)
    {
      perror (cfg);
      return SHISA_FOPEN_ERROR;
    }

  initbuffer (&lb);

  while (readlinebuffer (&lb, fh))
    {
      char *p = lb.buffer;
      char *q;

      p[lb.length - 1] = '\0';

      while (*p && strchr (" \t\r\n", *p))
	p++;

      if (*p == '\0' || *p == '#')
	continue;

      q = strchr (p, ' ');
      if (q && (strchr (p, '=') == NULL || q < strchr (p, '=')))
	*q = '=';

      shisa_cfg (dbh, p);
    }

  freebuffer (&lb);

  if (ferror (fh))
    return SHISA_IO_ERROR;

  if (fclose (fh) != 0)
    return SHISA_IO_ERROR;

  return SHISA_OK;
}

/**
 * shisa_cfg_print:
 * @dbh: Shisa library handle created by shisa().
 * @fh: file descriptor open for writing.
 *
 * Print library configuration status, mostly for debugging purposes.
 *
 * Return Value: Returns %SHISA_OK.
 **/
void
shisa_cfg_print (Shisa * dbh, FILE * fh)
{
  fprintf (fh, "Shisa initial library configuration:\n");
}

/**
 * shisa_cfg_default_systemfile:
 * @dbh: Shisa library handle created by shisa().
 *
 * Return value: Return system configuration filename.
 **/
const char *
shisa_cfg_default_systemfile (Shisa * dbh)
{
  return SYSTEMCFGFILE;
}
