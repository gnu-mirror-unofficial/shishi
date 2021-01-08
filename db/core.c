/* core.c --- Core Shisa database API.
 * Copyright (C) 2003-2021 Simon Josefsson
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
 * @realms: Returned pointer to a newly allocated array of also
 *   allocated and null-terminated UTF-8 strings with realm names.
 * @nrealms: Pointer to a number which is updated with the number
 *   of just allocated and returned realm strings.
 *
 * Extracts a list of all realm names in backend, as null-terminated
 * UTF-8 strings.  The caller is responsible for deallocating all
 * strings as well as the array *@realms.
 *
 * Return value: Returns %SHISA_OK on success, or an error code.
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
 * @realm: Name of realm, as null-terminated UTF-8 string.
 * @principals: Returned pointer to newly allocated array of just
 *   allocated null-terminated UTF-8 strings with principal names.
 * @nprincipals: Pointer to an integer updated with the number of just
 *   allocated and returned principal names.
 *
 * Extracts a list of all principal names in backend belonging to
 * the realm @realm, as null-terminated UTF-8 strings.  The caller
 * is responsible for deallocating all strings and the array
 * *@principals.
 *
 * Return value: Returns %SHISA_OK on success, %SHISA_NO_REALM if the
 *   specified realm does not exist, or an error code otherwise.
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
 * @realm: Name of the realm the principal belongs to.
 * @principal: Name of principal to get information about.
 * @ph: Pointer to a previously allocated principal structure
 *   where information about the principal is to be stored.
 *
 * Extracts information about given the PRINCIPAL@REALM pair
 * selected by @principal and @realm.
 *
 * Return value: Returns %SHISA_OK if successful, %SHISA_NO_REALM if
 *   the indicated realm does not exist, %SHISA_NO_PRINCIPAL if the
 *   indicated principal does not exist, or an error code otherwise.
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
 * @realm: Name of the realm the principal belongs to.
 * @principal: Name of principal to get information about.
 * @ph: Pointer to an existing principal structure containing
 * information to store in the database.
 *
 * Modifies information stored about the given principal
 * PRINCIPAL@REALM.  Note that it is usually a good idea to set
 * in @ph only the fields that are to be updated.
 *
 * It is generally suggested to first call shisa_principal_find(),
 * to get the current information, then to modify one field and
 * call shisa_principal_update().
 *
 * Modifying several values is not recommended in general,
 * as this will 1) overwrite any modifications made to other
 * fields between the two calls (by other processes) and
 * 2) will cause all values to be written again, which may
 * generate more overhead.
 *
 * Return value: Returns %SHISA_OK if successful, %SHISA_NO_REALM if
 *   the indicated realm does not exist, %SHISA_NO_PRINCIPAL if the
 *   indicated principal does not exist, or an error code otherwise.
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
 * @realm: Name of the realm the principal belongs to.
 * @principal: Name of principal to add.  When set to %NULL,
 *   only the realm @realm is created.
 * @ph: Pointer to a principal structure with information to store
 *   in the database.
 * @key: Pointer to a key structure with information to store in
 *   the database.
 *
 * Inserts the given information into the database for the
 * principal PRINCIPAL@REALM.  In case @principal is %NULL,
 * the parameters @ph and @key are not used, so only the realm
 * is added to the database.
 *
 * Return value: Returns %SHISA_OK if the information was
 *   successfully added, or an error code otherwise.
 **/
int
shisa_principal_add (Shisa * dbh,
		     const char *realm, const char *principal,
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
 * @realm: Name of the realm the principal belongs to.
 * @principal: Name of the principal to remove.  Set to %NULL,
 *   only the realm @realm is removed.
 *
 * Removes all information stored in the database for the given
 * principal PRINCIPAL@REALM.  When @principal is %NULL, then the
 * realm @realm is itself removed, but this can only succeed if
 * the realm is already empty of principals.
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
 * @realm: Name of the realm the principal belongs to.
 * @principal: Name of the principal whose keys are examined.
 * @hint: Pointer to a Shisa key structure with hints on matching
 *   criteria for relevant keys.  %NULL matches all keys.
 * @keys: Returned pointer to a newly allocated array of Shisa
 *   key structures.
 * @nkeys: Pointer to an integer updated with the number of
 *   allocated Shisa key structures in *@keys.
 *
 * Iterates through the set of keys belonging to PRINCIPAL@REALM,
 * as selected by @principal and @realm.  Then extracts any keys
 * that match the criteria in @hint.
 *
 * Not all elements of @hint need to be filled in.  Set only
 * the fields you are interested in.  For example, if you want
 * to extract all keys of etype 3, i.e., DES-CBC-MD5, then set
 * the field @key->etype to 3, and all other fields to zero.
 *
 * Return value: Returns %SHISA_OK if successful, or an error code.
 **/
int
shisa_keys_find (Shisa * dbh,
		 const char *realm, const char *principal,
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
 * @realm: Name of the realm the principal belongs to.
 * @principal: Name of the principal to add a new key for.
 * @key: Pointer to a Shisa key structure with the new key.
 *
 * Adds a complete key @key to the database entry belonging
 * to the principal PRINCIPAL@REALM, as set by @principal and @realm.
 *
 * Return value: Returns %SHISA_OK if successful, or an error code.
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
 * @realm: Name of the realm the principal belongs to.
 * @principal: Name of the principal needing an updated key.
 * @oldkey: Pointer to a Shisa key structure giving matching
 *   criteria for locating the key to be updated.
 * @newkey: Pointer to a complete Shisa key structure, in which
 *   all fields are used for the new key.  Note that @oldkey
 *   normally has far fewer fields filled-in.
 *
 * Modifies data about a key stored in the database, a key
 * belonging to the principal selected by @principal and @realm.
 * First @oldkey is used to locate the key to update, as does
 * shisa_keys_find().  Then the found key is modified to carry
 * whatever information is stored in @newkey.
 *
 * Not all elements of @oldkey need to be filled out, only
 * sufficiently many so as to uniquely identify the desired key.
 * For example, if you want to modify the information stored about
 * a unique key of etype 3, i.e., DES-CBC-MD5, then set the field
 * @key->etype to 3, leaving all other fields as zero.
 *
 * Return value: Returns %SHISA_OK on success, %SHISA_NO_KEY if no
 *   key could be located, %SHISA_MULTIPLE_KEY_MATCH if more
 *   than a single key matched the given criteria, or an error code
 *   otherwise.
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
 * @realm: Name of the realm the principal belongs to.
 * @principal: Name of the principal whose key is to be removed.
 * @key: Pointer to a Shisa key structure with hints on matching
 *   criteria for the key to select.
 *
 * Removes from the Shisa database a key, matching the hints in @key,
 * for the user PRINCIPAL@REALM.  Not all elements of @key need to be
 * filled in, only those relevant to locate the key uniquely.
 *
 * For example, if you want to remove the only key of etype 3,
 * i.e., DES-CBC-MD5, then set the field @key->etype to 3, and
 * all other fields to zero.
 *
 * Return value: Returns %SHISA_OK on success, %SHISA_NO_KEY if no key
 *   could be located, %SHISA_MULTIPLE_KEY_MATCH if more than one
 *   key matched the given criteria, or an error code otherwise.
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
 * @key: Pointer to a Shisa key structure to deallocate.
 *
 * Deallocates the fields of a Shisa key structure, as well as
 * the structure itself.
 **/
void
shisa_key_free (Shisa * dbh, Shisa_key * key)
{
  free (key->key);
  free (key->salt);
  free (key->str2keyparam);
  free (key->password);
  free (key);
}


/**
 * shisa_keys_free:
 * @dbh: Shisa library handle created by shisa().
 * @keys: Pointer to an array of Shisa key structures.
 * @nkeys: Number of key elements in the array @keys.
 *
 * Deallocates each key element in the array @keys of Shisa
 * database keys, using repeated calls to shisa_key_free().
 **/
void
shisa_keys_free (Shisa * dbh, Shisa_key ** keys, size_t nkeys)
{
  size_t i;

  for (i = 0; i < nkeys; i++)
    shisa_key_free (dbh, keys[i]);
}
