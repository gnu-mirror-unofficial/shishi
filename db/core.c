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

/**
 * shisa_enumerate_realms:
 * @dbh: Shisa library handle created by shisa().
 * @realms: pointer to newly allocated array of newly allocated
 *   zero-terminated UTF-8 strings indicating name of realm.
 * @nrealms: pointer to number indicating number of allocated realm strings.
 *
 * Extract a list of all realm names in backend, as zero-terminated
 * UTF-8 strings.  The caller must deallocate the strings.
 *
 * Return value: Returns SHISA_OK on success, or error code.
 **/
int
shisa_enumerate_realms (Shisa * dbh, char ***realms, size_t * nrealms)
{
  _Shisa_db *db;
  size_t i;
  int rc;

  *nrealms = 0;
  if (realms)
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

/**
 * shisa_enumerate_principals:
 * @dbh: Shisa library handle created by shisa().
 * @realm: name of realm, as zero-terminated UTF-8 string.
 * @principal: pointer to newly allocated array of newly allocated
 *   zero-terminated UTF-8 strings indicating name of principal.
 * @nprincipals: pointer to number indicating number of allocated
 *   realm strings.
 *
 * Extract a list of all principal names in realm in backend, as
 * zero-terminated UTF-8 strings.  The caller must deallocate the
 * strings.
 *
 * Return value: Returns SHISA_OK on success, SHISA_NO_REALM if the
 *   specified realm does not exist, or error code.
 **/
int
shisa_enumerate_principals (Shisa * dbh,
			    const char *realm,
			    char ***principals, size_t * nprincipals)
{
  _Shisa_db *db;
  size_t i;
  int rc;

  *nprincipals = 0;
  if (principals)
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
		      const char *realm,
		      const char *principal, Shisa_principal * ph)
{
  _Shisa_db *db;
  size_t i;
  int rc;

  for (i = 0, db = dbh->dbs; i < dbh->ndbs; i++, db++)
    {
      rc = db->backend->principal_find (dbh, db->state, realm, principal, ph);
      if (rc == SHISA_OK || (rc != SHISA_OK && rc != SHISA_NO_PRINCIPAL))
	return rc;
    }

  return SHISA_NO_PRINCIPAL;
}

int
shisa_principal_update (Shisa * dbh,
			const char *realm,
			const char *principal, const Shisa_principal * ph)
{
  _Shisa_db *db;
  size_t i;
  int rc;

  for (i = 0, db = dbh->dbs; i < dbh->ndbs; i++, db++)
    {
      /* XXX ignore read-only backends. */
      rc =
	db->backend->principal_update (dbh, db->state, realm, principal, ph);
      /* XXX ignore error and continue for ignore-error backends. */
      return rc;
    }

  return SHISA_ADD_PRINCIPAL_ERROR;
}

int
shisa_principal_add (Shisa * dbh,
		     const char *realm,
		     const char *principal,
		     const Shisa_principal * ph, const Shisa_key * key)
{
  _Shisa_db *db;
  size_t i;
  int rc;

  if (realm == NULL)
    return SHISA_NO_REALM;

  for (i = 0, db = dbh->dbs; i < dbh->ndbs; i++, db++)
    {
      /* XXX ignore read-only backends. */
      rc = db->backend->principal_add (dbh, db->state, realm,
				       principal, ph, key);
      /* XXX ignore error and continue for ignore-error backends. */
      return rc;
    }

  return SHISA_ADD_PRINCIPAL_ERROR;
}

int
shisa_principal_remove (Shisa * dbh, const char *realm, const char *principal)
{
  _Shisa_db *db;
  size_t i;
  int rc;

  if (realm == NULL)
    return SHISA_NO_REALM;

  for (i = 0, db = dbh->dbs; i < dbh->ndbs; i++, db++)
    {
      /* XXX ignore read-only backends. */
      rc = db->backend->principal_remove (dbh, db->state, realm, principal);
      /* XXX ignore error and continue for ignore-error backends. */
      return rc;
    }

  return SHISA_REMOVE_PRINCIPAL_ERROR;
}

int
shisa_keys_find (Shisa * dbh,
		 const char *realm,
		 const char *principal,
		 const Shisa_key *hint,
		 Shisa_key ***keys,
		 size_t * nkeys)
{
  _Shisa_db *db;
  size_t i;
  int rc;

  *nkeys = 0;
  if (keys)
    *keys = NULL;

  for (i = 0, db = dbh->dbs; i < dbh->ndbs; i++, db++)
    {
      rc = db->backend->keys_find (dbh, db->state, realm, principal, hint,
				   keys, nkeys);
      if (rc != SHISA_OK)
	/* XXX mem leak. */
	return rc;
    }

  return SHISA_OK;
}

int
shisa_key_add (Shisa * dbh,
	       const char *realm,
	       const char *principal,
	       const Shisa_key * key)
{
  _Shisa_db *db;
  size_t i;
  int rc;

  for (i = 0, db = dbh->dbs; i < dbh->ndbs; i++, db++)
    {
      rc = db->backend->key_add (dbh, db->state, realm, principal, key);
      if (rc != SHISA_OK)
	return rc;
    }

  return SHISA_OK;
}


int
shisa_key_update (Shisa * dbh,
		  const char *realm,
		  const char *principal,
		  const Shisa_key * oldkey,
		  const Shisa_key * newkey)
{
  _Shisa_db *db;
  size_t i;
  int rc;

  for (i = 0, db = dbh->dbs; i < dbh->ndbs; i++, db++)
    {
      rc = db->backend->key_update (dbh, db->state, realm, principal,
				    oldkey, newkey);
      if (rc != SHISA_OK)
	return rc;
    }

  return SHISA_OK;
}

int
shisa_key_remove (Shisa * dbh,
		  const char *realm,
		  const char *principal,
		  const Shisa_key * key)
{
  _Shisa_db *db;
  size_t i;
  int rc;

  for (i = 0, db = dbh->dbs; i < dbh->ndbs; i++, db++)
    {
      rc = db->backend->key_remove (dbh, db->state, realm, principal, key);
      if (rc != SHISA_OK)
	return rc;
    }

  return SHISA_OK;
}

void
shisa_key_free (Shisa * dbh, Shisa_key * key)
{
  if (key->key)
    free (key->key);
  if (key->salt)
    free (key->salt);
  if (key->str2keyparam)
    free (key->str2keyparam);
  if (key->password)
    free (key->password);
  free (key);
}


void
shisa_keys_free (Shisa * dbh, Shisa_key ** keys, size_t nkeys)
{
  size_t i;

  for (i = 0; i < nkeys; i++)
    shisa_key_free (dbh, keys[i]);
}
