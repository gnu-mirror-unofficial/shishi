/* core.c --- Core Shisa database API.
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
shisa_enumerate_realms (Shisa *dbh,
			char ***realms,
			size_t *nrealms)
{
  _Shisa_db *db;
  size_t i;
  int rc;

  *nrealms = 0;
  *realms = NULL;

  for (i = 0, db = dbh->dbs; i < dbh->ndbs; i++, db++)
    {
      rc = db->backend->enumerate_realms (dbh, db->state, realms, nrealms);
      if (rc != SHISA_OK)
	/* XXX mem leak. */
	return rc;
    }

  return SHISA_OK;
}

int
shisa_enumerate_principals (Shisa *dbh,
			    const char *realm,
			    char ***principals,
			    size_t *nprincipals)
{
  _Shisa_db *db;
  size_t i;
  int rc;

  *nprincipals = 0;
  *principals = NULL;

  for (i = 0, db = dbh->dbs; i < dbh->ndbs; i++, db++)
    {
      rc = db->backend->enumerate_principals (dbh, db->state, realm,
					      principals, nprincipals);
      if (rc != SHISA_OK)
	/* XXX mem leak. */
	return rc;
    }

  return SHISA_OK;
}

int
shisa_principal_find (Shisa * dbh,
		      const char *client,
		      const char *realm,
		      Shisa_principal **ph)
{
  _Shisa_db *db;
  size_t i;
  int rc;

  for (i = 0, db = dbh->dbs; i < dbh->ndbs; i++, db++)
    {
      rc = db->backend->principal_find (dbh, db->state, client, realm, ph);
      if (rc == SHISA_OK || (rc != SHISA_OK && rc != SHISA_NO_PRINCIPAL))
	return rc;
    }

  return SHISA_NO_PRINCIPAL;
}

void
shisa_principal_free (Shisa_principal *ph)
{
  if (ph)
    {
      if (ph->name)
	free (ph->name);
      if (ph->realm)
	free (ph->realm);
      free (ph);
    }

}
