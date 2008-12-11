/* keys.c --- Functions for managing keys sets, and keys stored in files.
 * Copyright (C) 2002, 2003, 2004, 2006, 2007  Simon Josefsson
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#include "internal.h"

struct Shishi_keys
{
  Shishi *handle;
  Shishi_key **keys;
  int nkeys;
};

/**
 * shishi_keys:
 * @handle: shishi handle as allocated by shishi_init().
 * @keys: output pointer to newly allocated keys handle.
 *
 * Get a new key set handle.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_keys (Shishi * handle, Shishi_keys ** keys)
{
  *keys = xmalloc (sizeof (**keys));

  (*keys)->handle = handle;
  (*keys)->keys = NULL;
  (*keys)->nkeys = 0;

  return SHISHI_OK;
}

/**
 * shishi_keys_done:
 * @keys: key set handle as allocated by shishi_keys().
 *
 * Deallocates all resources associated with key set.  The key set
 * handle must not be used in calls to other shishi_keys_*() functions
 * after this.
 **/
void
shishi_keys_done (Shishi_keys ** keys)
{
  size_t i;

  if (!keys || !*keys)
    return;

  if ((*keys)->nkeys > 0)
    for (i = (*keys)->nkeys; i > 0; i--)
      shishi_key_done ((*keys)->keys[i - 1]);

  if ((*keys)->keys)
    free ((*keys)->keys);

  free (*keys);

  *keys = NULL;

  return;
}

/**
 * shishi_keys_size:
 * @keys: key set handle as allocated by shishi_keys().
 *
 * Get size of key set.
 *
 * Return value: Returns number of keys stored in key set.
 **/
int
shishi_keys_size (Shishi_keys * keys)
{
  return keys->nkeys;
}

/**
 * shishi_keys_nth:
 * @keys: key set handle as allocated by shishi_keys().
 * @keyno: integer indicating requested key in key set.
 *
 * Get the n:th ticket in key set.
 *
 * Return value: Returns a key handle to the keyno:th key in the key
 *   set, or NULL if @keys is invalid or @keyno is out of bounds.  The
 *   first key is @keyno 0, the second key @keyno 1, and so on.
 **/
const Shishi_key *
shishi_keys_nth (Shishi_keys * keys, int keyno)
{
  if (keys == NULL || keyno >= keys->nkeys)
    return NULL;

  return keys->keys[keyno];
}

/**
 * shishi_keys_remove:
 * @keys: key set handle as allocated by shishi_keys().
 * @keyno: key number of key in the set to remove.  The first
 *   key is key number 0.
 *
 * Remove a key, indexed by @keyno, in given key set.
 **/
void
shishi_keys_remove (Shishi_keys * keys, int keyno)
{
  shishi_key_done (keys->keys[keyno]);

  if (keyno < keys->nkeys)
    memmove (&keys->keys[keyno], &keys->keys[keyno + 1],
	     sizeof (*keys->keys) * (keys->nkeys - keyno - 1));

  --keys->nkeys;

  keys->keys = xrealloc (keys->keys, sizeof (*keys->keys) * keys->nkeys);
}

/**
 * shishi_keys_add:
 * @keys: key set handle as allocated by shishi_keys().
 * @key: key to be added to key set.
 *
 * Add a key to the key set.  A deep copy of the key is stored, so
 * changing @key, or deallocating it, will not modify the value stored
 * in the key set.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_keys_add (Shishi_keys * keys, Shishi_key * key)
{
  int rc;

  if (!key)
    return SHISHI_INVALID_KEY;

  keys->nkeys++;

  keys->keys = xrealloc (keys->keys, sizeof (*keys->keys) * keys->nkeys);

  rc = shishi_key (keys->handle, &(keys->keys[keys->nkeys - 1]));
  if (rc != SHISHI_OK)
    return rc;

  shishi_key_copy (keys->keys[keys->nkeys - 1], key);

  return SHISHI_OK;
}

/**
 * shishi_keys_print:
 * @keys: key set to print.
 * @fh: file handle, open for writing, to print keys to.
 *
 * Print all keys in set using shishi_key_print.
 *
 * Returns: Returns %SHISHI_OK on success.
 **/
int
shishi_keys_print (Shishi_keys * keys, FILE *fh)
{
  int rc;
  int i;

  for (i = 0; i < keys->nkeys; i++)
    {
      rc = shishi_key_print (keys->handle, fh, shishi_keys_nth (keys, i));
      if (rc != SHISHI_OK)
	return rc;

      fprintf (fh, "\n");
    }

  return SHISHI_OK;
}

/**
 * shishi_keys_to_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @filename: filename to append key to.
 * @keys: set of keys to print.
 *
 * Print an ASCII representation of a key structure to a file, for
 * each key in the key set.  The file is appended to if it exists.
 * See shishi_key_print() for the format of the output.
 *
 * Return value: Returns %SHISHI_OK iff successful.
 **/
int
shishi_keys_to_file (Shishi * handle,
		     const char *filename,
		     Shishi_keys * keys)
{
  FILE *fh;
  int res;

  if (VERBOSE (handle))
    printf (_("Writing KEYS to %s...\n"), filename);

  fh = fopen (filename, "a");
  if (fh == NULL)
    return SHISHI_FOPEN_ERROR;

  res = shishi_keys_print (keys, fh);
  if (res != SHISHI_OK)
    return res;

  res = fclose (fh);
  if (res != 0)
    return SHISHI_IO_ERROR;

  if (VERBOSE (handle))
    printf (_("Writing KEYS to %s...done\n"), filename);

  return SHISHI_OK;
}

/**
 * shishi_keys_for_serverrealm_in_file
 * @handle: Shishi library handle create by shishi_init().
 * @filename: file to read keys from.
 * @server: server name to get key for.
 * @realm: realm of server to get key for.
 *
 * Get keys that match specified @server and @realm from the key set
 * file @filename.
 *
 * Return value: Returns the key for specific server and realm, read
 *   from the indicated file, or NULL if no key could be found or an
 *   error encountered.
 **/
Shishi_key *
shishi_keys_for_serverrealm_in_file (Shishi * handle,
				     const char *filename,
				     const char *server, const char *realm)
{
  Shishi_key *key = NULL;
  FILE *fh;
  int res;

  fh = fopen (filename, "r");
  if (fh == NULL)
    return NULL;

  res = SHISHI_OK;
  while (!feof (fh))
    {
      res = shishi_key_parse (handle, fh, &key);
      if (res != SHISHI_OK || key == NULL)
	break;

      if (VERBOSENOISE (handle))
	{
	  printf ("Read key:\n");
	  shishi_key_print (handle, stdout, key);
	}

      if ((!server ||
	   (shishi_key_principal (key) &&
	    strcmp (server, shishi_key_principal (key)) == 0)) &&
	  (!realm ||
	   (shishi_key_realm (key) &&
	    strcmp (realm, shishi_key_realm (key)) == 0)))
	break;

      shishi_key_done (key);
      key = NULL;
    }

  res = fclose (fh);
  if (res != 0)
    return NULL;

  return key;
}

/**
 * shishi_keys_for_server_in_file
 * @handle: Shishi library handle create by shishi_init().
 * @filename: file to read keys from.
 * @server: server name to get key for.
 *
 * Get key for specified @server from @filename.
 *
 * Return value: Returns the key for specific server, read from the
 *   indicated file, or NULL if no key could be found or an error
 *   encountered.
 **/
Shishi_key *
shishi_keys_for_server_in_file (Shishi * handle,
				const char *filename, const char *server)
{
  return shishi_keys_for_serverrealm_in_file (handle, filename, server, NULL);
}

/**
 * shishi_keys_for_localservicerealm_in_file:
 * @handle: Shishi library handle create by shishi_init().
 * @filename: file to read keys from.
 * @service: service to get key for.
 * @realm: realm of server to get key for, or NULL for default realm.
 *
 * Get key for specified @service and @realm from @filename.
 *
 * Return value: Returns the key for the server
 * "SERVICE/HOSTNAME@REALM" (where HOSTNAME is the current system's
 * hostname), read from the default host keys file (see
 * shishi_hostkeys_default_file()), or NULL if no key could be found
 * or an error encountered.
 **/
Shishi_key *
shishi_keys_for_localservicerealm_in_file (Shishi * handle,
					   const char *filename,
					   const char *service,
					   const char *realm)
{
  char *hostname;
  char *server;
  Shishi_key *key;

  hostname = xgethostname ();

  asprintf (&server, "%s/%s", service, hostname);

  key = shishi_keys_for_serverrealm_in_file (handle, filename, server, realm);

  free (server);
  free (hostname);

  return key;
}
