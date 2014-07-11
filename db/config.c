/* cfg.c --- Read Shisa Configuration file.
 * Copyright (C) 2002-2013 Simon Josefsson
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#include "info.h"

/**
 * shisa_cfg_db:
 * @dbh: Shisa library handle created by shisa().
 * @value: String containing database definition.
 *
 * Sets up and opens a new database.  The syntax of the parameter
 * @value is "TYPE[ LOCATION[ PARAMETER]]", where TYPE is one of
 * the supported database types, typically "file".
 *
 * The above substrings LOCATION and PARAMETER are optional strings
 * passed on verbatim to the database during initialization.
 * Neither TYPE nor LOCATION may contain embedded spaces,
 * but PARAMETER may do so.
 *
 * Return Value: Returns %SHISA_OK if a database was parsed and opened
 *   successfully.
 **/
int
shisa_cfg_db (Shisa * dbh, const char *value)
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
      shisa_info (dbh, "Unknown database type: `%s'.", db);
      free (db);
      return SHISA_CFG_SYNTAX_ERROR;
    }

  rc = backend->init (dbh, location, options, &state);
  if (rc != SHISA_OK)
    {
      shisa_info (dbh, "Cannot initialize `%s' database backend.\n"
		  "Location `%s' and options `%s'.", db,
		  location ? location : "N/A", options ? options : "N/A");
      free (db);
      return rc;
    }
  free (db);

  dbh->dbs = xrealloc (dbh->dbs, ++dbh->ndbs * sizeof (*dbh->dbs));
  dbh->dbs->backend = backend;
  dbh->dbs->state = state;

  return SHISA_OK;
}

/**
 * shisa_cfg:
 * @dbh: Shisa library handle created by shisa().
 * @option: String with options to prime the Shisa library.
 *
 * Configures the Shisa library from the specification @option.
 * This call expects a string declaration of the form "db=VALUE",
 * or "db VALUE".  Here VALUE is the same declaration as used by
 * shisa_cfg_db(), i.e., of the form "TYPE[ LOCATION[ PARAMETER]]".
 *
 * The prefix "db", mandatory in @option, makes shisa_cfg() suited
 * to a syntax with key-value pairs also in PARAMETER.
 *
 * Return Value: Returns %SHISA_OK if @option is valid.
 **/
int
shisa_cfg (Shisa * dbh, const char *option)
{
  int rc;

  if (!option)
    return SHISA_OK;

  if (strncmp (option, "db=", 3) != 0 && strncmp (option, "db ", 3) != 0)
    {
      shisa_info (dbh, "Unknown option: `%s'.", option);
      return SHISA_CFG_SYNTAX_ERROR;
    }

  rc = shisa_cfg_db (dbh, option + 3);
  if (rc != SHISA_OK)
    return rc;

  return SHISA_OK;
}

/**
 * shisa_cfg_from_file:
 * @dbh: Shisa library handle created by shisa().
 * @cfg: File name where to read configuration.
 *
 * Configures the Shisa library using a configuration file
 * located at @cfg.
 *
 * Return Value: Returns %SHISA_OK if successful.  Typically
 *   returns %SHISA_CFG_NO_FILE in response to a misnamed file.
 **/
int
shisa_cfg_from_file (Shisa * dbh, const char *cfg)
{
  char *line = NULL;
  size_t len = 0;
  FILE *fh;
  int rc = SHISA_OK;

  if (cfg == NULL)
    return SHISA_OK;

  fh = fopen (cfg, "r");
  if (fh == NULL)
    {
      perror (cfg);
      return SHISA_CFG_NO_FILE;
    }

  while (!feof (fh))
    {
      ssize_t n = getline (&line, &len, fh);
      char *p = line;
      char *q;

      if (n <= 0)
	/* End of file or error.  */
	break;

      while (strlen (p) > 0 && (p[strlen (p) - 1] == '\n' ||
				p[strlen (p) - 1] == '\r'))
	p[strlen (p) - 1] = '\0';

      while (*p && strchr (" \t\r\n", *p))
	p++;

      if (*p == '\0' || *p == '#')
	continue;

      q = strchr (p, ' ');
      if (q && (strchr (p, '=') == NULL || q < strchr (p, '=')))
	*q = '=';

      rc = shisa_cfg (dbh, p);
      if (rc != SHISA_OK)
	break;
    }

  free (line);

  if (ferror (fh))
    if (rc == SHISA_OK)
      return SHISA_CFG_IO_ERROR;

  if (fclose (fh) != 0)
    if (rc == SHISA_OK)
      return SHISA_CFG_IO_ERROR;

  return rc;
}

/**
 * shisa_cfg_default_systemfile:
 * @dbh: Shisa library handle created by shisa().
 *
 * Fetches information on the installed configuration.
 *
 * Return value: Returns file name of the active
 *   system configuration.
 **/
const char *
shisa_cfg_default_systemfile (Shisa * dbh)
{
  return SYSTEMCFGFILE;
}
