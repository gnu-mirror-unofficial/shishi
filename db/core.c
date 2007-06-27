/* core.c --- Core Shisa database API.
 * Copyright (C) 2003, 2007  Simon Josefsson
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
 * shisa_enumerate_realms:
 * @dbh: Shisa library handle created by shisa().
 * @realms: Pointer to newly allocated array of newly allocated
 *   zero-terminated UTF-8 strings indicating name of realm.
 * @nrealms: Pointer to number indicating number of allocated realm strings.
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
 * @realm: Name of realm, as zero-terminated UTF-8 string.
 * @principal: Pointer to newly allocated array of newly allocated
 *   zero-terminated UTF-8 strings indicating name of principal.
 * @nprincipals: Pointer to number indicating number of allocated
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

/**
 * shisa_principal_find:
 * @dbh: Shisa library handle created by shisa().
 * @realm: Name of realm the principal belongs in.
 * @principal: Name of principal to get information on.
 * @ph: Pointer to previously allocated principal structure to fill
 *   out with information about principal.
 *
 * Extract information about given PRINCIPAL@REALM.
 *
 * Return value: Returns %SHISA_OK iff successful, %SHISA_NO_REALM if
 *   the indicated realm does not exist, %SHISA_NO_PRINCIPAL if the
 *   indicated principal does not exist, or an error code.
 **/
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

/**
 * shisa_principal_update:
 * @dbh: Shisa library handle created by shisa().
 * @realm: Name of realm the principal belongs in.
 * @principal: Name of principal to get information on.
 * @ph: Pointer to principal structure with information to store in database.
 *
 * Modify information stored for given PRINCIPAL@REALM.  Note that it
 * is usually a good idea to only set the fields in @ph that you
 * actually want to update.  Specifically, first calling
 * shisa_principal_find() to get the current information, then
 * modifying one field, and calling shisa_principal_update() is not
 * recommended in general, as this will 1) overwrite any modifications
 * made to other fields between the two calls (by other processes) and
 * 2) will cause all values to be written again, which may generate
 * more overhead.
 *
 * Return value: Returns SHISA_OK if successful, %SHISA_NO_REALM if
 *   the indicated realm does not exist, %SHISA_NO_PRINCIPAL if the
 *   indicated principal does not exist, or an error code.
 **/
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

/**
 * shisa_principal_add:
 * @dbh: Shisa library handle created by shisa().
 * @realm: Name of realm the principal belongs in.
 * @principal: Name of principal to add, may be %NULL to indicate that
 *   the @realm should be created, in which case @ph and @key are not used.
 * @ph: Pointer to principal structure with information to store in database.
 * @key: Pointer to key structure with information to store in database.
 *
 * Add given information to database as PRINCIPAL@REALM.
 *
 * Return value: Returns SHISA_OK iff successfully added, or an error code.
 **/
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

/**
 * shisa_principal_remove:
 * @dbh: Shisa library handle created by shisa().
 * @realm: Name of realm the principal belongs in.
 * @principal: Name of principal to remove, may be %NULL to indicate
 *   that the @realm itself should be removed (requires that the realm
 *   to be empty).
 *
 * Remove all information stored in the database for given PRINCIPAL@REALM.
 *
 * Return value: Returns %SHISA_OK if successful, or an error code.
 **/
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

/**
 * shisa_keys_find:
 * @dbh: Shisa library handle created by shisa().
 * @realm: Name of realm the principal belongs in.
 * @principal: Name of principal to add key for.
 * @hint: Pointer to Shisa key structure with hints on matching the key
 *   to modify, may be %NULL to match all keys.
 * @keys: pointer to newly allocated array with Shisa key structures.
 * @nkeys: pointer to number of newly allocated Shisa key structures in @keys.
 *
 * Iterate through keys for given PRINCIPAL@REALM and extract any keys
 * that match @hint.  Not all elements of @hint need to be filled out,
 * only use the fields you are interested in.  For example, if you
 * want to extract all keys with an etype of 3 (DES-CBC-MD5), set the
 * @key->etype field to 3, and set all other fields to 0.
 *
 * Return value: Returns %SHISA_OK iff successful, or an error code.
 **/
int
shisa_keys_find (Shisa * dbh,
		 const char *realm,
		 const char *principal,
		 const Shisa_key * hint, Shisa_key *** keys, size_t * nkeys)
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

/**
 * shisa_key_add:
 * @dbh: Shisa library handle created by shisa().
 * @realm: Name of realm the principal belongs in.
 * @principal: Name of principal to add key for.
 * @key: Pointer to Shisa key structure with key to add.
 *
 * Add key to database for given PRINCIPAL@REALM.
 *
 * Return value: Returns %SHISA_OK iff successful, or an error code.
 **/
int
shisa_key_add (Shisa * dbh,
	       const char *realm,
	       const char *principal, const Shisa_key * key)
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


/**
 * shisa_key_update:
 * @dbh: Shisa library handle created by shisa().
 * @realm: Name of realm the principal belongs in.
 * @principal: Name of principal to remove key for.
 * @oldkey: Pointer to Shisa key structure with hints on matching the key
 *   to modify.
 * @newkey: Pointer to Shisa key structure with new values for the
 *   key, note that all fields are used (and not just the ones specified
 *   by @oldkey).
 *
 * Modify data about a key in the database, for the given
 * PRINCIPAL@REALM.  First the @oldkey is used to locate the key to
 * update (similar to shisa_keys_find()), then that key is modified to
 * contain whatever information is stored in @newkey.  Not all
 * elements of @oldkey need to be filled out, only enough as to
 * identify the key uniquely.  For example, if you want to modify the
 * information stored for the only key with an etype of 3
 * (DES-CBC-MD5), set the @key->etype field to 3, and set all other
 * fields to 0.
 *
 * Return value: Returns %SHISA_OK on success, %SHISA_NO_KEY if no key
 *   could be identified, and %SHISA_MULTIPLE_KEY_MATCH if more than one
 *   key matched the given criteria, or an error code.
 **/
int
shisa_key_update (Shisa * dbh,
		  const char *realm,
		  const char *principal,
		  const Shisa_key * oldkey, const Shisa_key * newkey)
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

/**
 * shisa_key_remove:
 * @dbh: Shisa library handle created by shisa().
 * @realm: Name of realm the principal belongs in.
 * @principal: Name of principal to remove key for.
 * @key: Pointer to Shisa key structure with hints on matching the key
 *   to remove.
 *
 * Remove a key, matching the hints in @key, from the Shisa database
 * for the user PRINCIPAL@REALM.  Not all elements of @key need to be
 * filled out, only those you are interested in.  For example, if you
 * want to remove the only key with an etype of 3 (DES-CBC-MD5), set
 * the @key->etype field to 3, and set all other fields to 0.
 *
 * Return value: Returns %SHISA_OK on success, %SHISA_NO_KEY if no key
 *   could be identified, and %SHISA_MULTIPLE_KEY_MATCH if more than one
 *   key matched the given criteria, or an error code.
 **/
int
shisa_key_remove (Shisa * dbh,
		  const char *realm,
		  const char *principal, const Shisa_key * key)
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

/**
 * shisa_key_free:
 * @dbh: Shisa library handle created by shisa().
 * @key: Pointer to Shisa key structure to deallocate.
 *
 * Deallocate the fields of a Shisa key structure, and the structure
 * itself.
 **/
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


/**
 * shisa_keys_free:
 * @dbh: Shisa library handle created by shisa().
 * @keys: Pointer to array with @nkeys elements of keys.
 * @nkeys: Number of key elements in @keys array.
 *
 * Deallocate each element of an array with Shisa database keys, using
 * shisa_key_free().
 **/
void
shisa_keys_free (Shisa * dbh, Shisa_key ** keys, size_t nkeys)
{
  size_t i;

  for (i = 0; i < nkeys; i++)
    shisa_key_free (dbh, keys[i]);
}
