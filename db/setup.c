/* init.c --- Initialization functions for the Shisa library.
 * Copyright (C) 2002-2021 Simon Josefsson
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
 * shisa:
 *
 * Initializes the Shisa library.  If this function fails, it may
 * print diagnostic errors to standard error.
 *
 * Return value: Returns a Shisa library handle, or %NULL on error.
 **/
Shisa *
shisa (void)
{
  Shisa *dbh;

  dbh = xcalloc (1, sizeof (*dbh));

  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  return dbh;
}

/**
 * shisa_done:
 * @dbh: Shisa handle as allocated by shisa().
 *
 * Deallocates the shisa library handle.  The handle must not be used
 * in calls to any shisa function after the completion of this call.
 **/
void
shisa_done (Shisa * dbh)
{
  _Shisa_db *db;
  size_t i;

  for (i = 0, db = dbh->dbs; i < dbh->ndbs; i++, db++)
    db->backend->done (dbh, db->state);

  free (dbh->dbs);
  free (dbh);
}

/**
 * shisa_init:
 * @dbh: Returned pointer to a created Shisa library handle.
 *
 * Creates a Shisa library handle, using shisa(), reading the system
 * configuration file from its default location.  The path to the
 * default system configuration file is decided at compile time
 * ($sysconfdir/shisa.conf).
 *
 * The handle is allocated regardless of return value, the only
 * exception being %SHISA_INIT_ERROR, which indicates a problem
 * in allocating the handle.  Other error conditions arise while
 * reading a file.
 *
 * Return value: Returns %SHISA_OK, or an error code.  The value
 *   %SHISA_INIT_ERROR indicates a failure to create the handle.
 **/
int
shisa_init (Shisa ** dbh)
{
  return shisa_init_with_paths (dbh, NULL);
}

/**
 * shisa_init_with_paths:
 * @dbh: Returned pointer to a created Shisa library handle.
 * @file: Filename of system configuration, or %NULL.
 *
 * Creates a Shisa library handle, using shisa(), but reading
 * the system configuration file at the location @file, or at
 * the default location, should @file be %NULL.  The path to
 * the default system configuration file is decided at compile
 * time ($sysconfdir/shisa.conf).
 *
 * The handle is allocated regardless of return value, the only
 * exception being %SHISA_INIT_ERROR, which indicates a problem
 * in allocating the handle.  Other error conditions arise while
 * reading a file.
 *
 * Return value: Returns %SHISA_OK, or an error code.  The value
 *   %SHISA_INIT_ERROR indicates a failure to create the handle.
 **/
int
shisa_init_with_paths (Shisa ** dbh, const char *file)
{
  int rc;

  if (!dbh || !(*dbh = shisa ()))
    return SHISA_INIT_ERROR;

  if (!file)
    file = shisa_cfg_default_systemfile (*dbh);

  rc = shisa_cfg_from_file (*dbh, file);
  if (rc != SHISA_OK && rc != SHISA_CFG_NO_FILE)
    return rc;

  if ((*dbh)->ndbs == 0)
    {
      rc = shisa_cfg (*dbh, "db file " DEFAULTDBPATH);
      if (rc != SHISA_OK)
	return rc;
    }

  return SHISA_OK;
}
