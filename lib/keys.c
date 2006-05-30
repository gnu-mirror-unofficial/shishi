/* keys.c --- Functions for managing keys sets, and keys stored in files.
 * Copyright (C) 2002, 2003, 2004, 2006  Simon Josefsson
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
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
    for (i = (*keys)->nkeys + 1; i > 0; i--)
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
 * shishi_keys_add_keytab_mem:
 * @handle: shishi handle as allocated by shishi_init().
 * @data: constant memory buffer with keytab of @len size.
 * @len: size of memory buffer with keytab data.
 * @keys: allocated key set to store keys in.
 *
 * Read keys from a MIT keytab data structure, and add them to the key
 * set.
 *
 * The format of keytab's is proprietary, and this function support
 * the 0x0501 and 0x0502 formats.  See the section The MIT Kerberos
 * Keytab Binary File Format in the Shishi manual for a description of
 * the reverse-engineered format.
 *
 * Returns: Returns %SHISHI_KEYTAB_ERROR if the data does not
 *   represent a valid keytab structure, and %SHISHI_OK on success.
 **/
int
shishi_keys_add_keytab_mem (Shishi * handle,
			    const char *data, size_t len,
			    Shishi_keys *keys)
{
  int rc;
  uint16_t file_format_version;
  size_t entrystartpos;
  uint16_t num_components;    /* sub 1 if version 0x501 */
  char *principal;
  size_t i, l;
  Shishi_key *key;

  if (VERBOSENOISE (handle))
    {
      printf ("keytab len %d (0x%x)\n", len, len);
      _shishi_hexprint (data, len);
    }

  /* Check file format. */
  file_format_version = (data[0] << 8) | data[1];

  if (VERBOSENOISE (handle))
    printf ("keytab file_format_version %04X\n", file_format_version);

  if (file_format_version != 0x0501 && file_format_version != 0x0502)
    return SHISHI_KEYTAB_ERROR;

  /* Check file integrity first, to avoid error-checking below. */
  entrystartpos = 2;
  while (entrystartpos < len)
    {
      int32_t size = data[entrystartpos] << 24 | data[entrystartpos+1] << 16
	| data[entrystartpos+2] << 8 | data[entrystartpos+3];
      entrystartpos += 4;

      if (VERBOSENOISE (handle))
	{
	  printf ("keytab size %d (%x)\n", size, size);
	  printf ("keytab pos %d < %d\n", entrystartpos + size, len);
	}

      if (entrystartpos + size > len)
	return SHISHI_KEYTAB_ERROR;

      /* Go to next entry... */
      entrystartpos += size;
    }
  if (entrystartpos != len)
    return SHISHI_KEYTAB_ERROR;

  rc = shishi_key (handle, &key);
  if (rc != SHISHI_OK)
    return rc;

  entrystartpos = 2;
  while (entrystartpos < len)
    {
      size_t pos = entrystartpos;
      uint16_t size = data[pos] << 24 | data[pos+1] << 16
	| data[pos+2] << 8 | data[pos+3];
      pos += 4;

      if (VERBOSENOISE (handle))
	printf ("keytab size %d (%x)\n", size, size);

      /* Num_components */
      num_components = data[pos] << 8 | data[pos+1];
      pos += 2;

      if (file_format_version == 0x0501)
	num_components--;

      /* Realm */
      {
	uint16_t realmlen = data[pos] << 8 | data[pos+1];
	char *realm = xstrndup (&data[pos + 2], realmlen);;

	pos += 2 + realmlen;

	shishi_key_realm_set (key, realm);
	free (realm);
      }

      /* Principal components. */
      for (i = 0; i < num_components; i++)
	{
	  size_t l;

	  l = data[pos] << 8 | data[pos+1];
	  pos += 2;
	  principal = xstrndup (&data[pos], l);
	  pos += l;
	  printf ("princ %s\n", principal);

	}
      //shishi_key_principal_set (key,

      /* Name_type */
      {
	uint32_t name_type   /* not present if version 0x501 */
	  = data[pos] << 24 | data[pos+1] << 16
	  | data[pos+2] << 8 | data[pos+3];
	pos += 4;

	if (VERBOSENOISE (handle))
	  printf ("keytab nametype %d (0x%08x)\n", name_type, name_type);
      }

      /* Timestamp */
      {
	uint32_t timestamp = data[pos] << 24 | data[pos+1] << 16
	  | data[pos+2] << 8 | data[pos+3];
	pos += 4;

	if (VERBOSENOISE (handle))
	  printf ("keytab timestamp %u (0x%08ux)\n", timestamp, timestamp);
      }

      /* keyvno8 */
      {
	uint8_t vno8 = data[pos++];

	if (VERBOSENOISE (handle))
	  printf ("keytab kvno8 %d (0x%02x)\n", vno8, vno8);

	shishi_key_version_set (key, vno8);
      }

      /* key, keytype */
      {
	uint32_t keytype = data[pos] << 8 | data[pos+1];
	pos += 2;

	if (VERBOSENOISE (handle))
	  printf ("keytab keytype %d (0x%x)\n", keytype, keytype);

	shishi_key_type_set (key, keytype);
      }

      /* key, length and data */
      {
	uint16_t keylen = data[pos] << 8 | data[pos+1];
	pos += 2;

	if (VERBOSENOISE (handle))
	  printf ("keytab keylen %d (0x%x) eq? %d\n", keylen, keylen,
		  shishi_key_length (key));

	if (VERBOSENOISE (handle))
	  _shishi_hexprint (data + pos, keylen);

	shishi_key_value_set (key, data + pos);
	pos += keylen;
      }

      if (pos - entrystartpos < size + 4)
	{
	  uint32_t vno /* only present if >= 4 bytes left in entry */
	    = data[pos] << 24 | data[pos+1] << 16
	    | data[pos+2] << 8 | data[pos+3];
	  pos += 4;

	  if (VERBOSENOISE (handle))
	    printf ("keytab kvno %d (0x%08x)\n", vno, vno);

	  shishi_key_version_set (key, vno);
	}

      rc = shishi_keys_add (keys, key);
      if (rc != SHISHI_OK)
	goto done;

      /* Go to next entry... */
      entrystartpos += size + 4;
    }

  rc = SHISHI_OK;

 done:
  shishi_key_done (key);

  return rc;
}

/**
 * shishi_keys_add_keytab_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @filename: name of file to read.
 * @keys: allocated key set to store keys in.
 *
 * Read keys from a MIT keytab data structure from a file, and add the
 * keys to the key set.
 *
 * The format of keytab's is proprietary, and this function support
 * the 0x0501 and 0x0502 formats.  See the section The MIT Kerberos
 * Keytab Binary File Format in the Shishi manual for a description of
 * the reverse-engineered format.
 *
 * Returns: Returns %SHISHI_IO_ERROR if the file cannot be read,
 *   %SHISHI_KEYTAB_ERROR if the data cannot be parsed as a valid keytab
 *   structure, and %SHISHI_OK on success.
 **/
int
shishi_keys_add_keytab_file (Shishi * handle,
			     const char *filename,
			     Shishi_keys *keys)
{
  size_t len;
  char *keytab = strfile (filename, &len);
  int rc;

  if (!keytab)
    return SHISHI_IO_ERROR;

  rc = shishi_keys_add_keytab_mem (handle, keytab, len, keys);

  free (keytab);

  return rc;
}

/**
 * shishi_keys_from_keytab_mem:
 * @handle: shishi handle as allocated by shishi_init().
 * @data: constant memory buffer with keytab of @len size.
 * @len: size of memory buffer with keytab data.
 * @outkeys: pointer to key set that will be allocated and populated,
 *   must be deallocated by caller on succes.
 *
 * Create a new key set populated with keys from a MIT keytab data
 * structure read from a memory block.
 *
 * The format of keytab's is proprietary, and this function support
 * the 0x0501 and 0x0502 formats.  See the section The MIT Kerberos
 * Keytab Binary File Format in the Shishi manual for a description of
 * the reverse-engineered format.
 *
 * Returns: Returns %SHISHI_KEYTAB_ERROR if the data does not
 *   represent a valid keytab structure, and %SHISHI_OK on success.
 **/
int
shishi_keys_from_keytab_mem (Shishi * handle,
			     const char *data, size_t len,
			     Shishi_keys **outkeys)
{
  int rc;

  rc = shishi_keys (handle, outkeys);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_keys_add_keytab_mem (handle, data, len, *outkeys);
  if (rc != SHISHI_OK)
    {
      shishi_keys_done (outkeys);
      return rc;
    }

  return SHISHI_OK;
}

/**
 * shishi_keys_from_keytab_file:
 * @handle: shishi handle as allocated by shishi_init().
 * @filename: name of file to read.
 * @outkeys: pointer to key set that will be allocated and populated,
 *   must be deallocated by caller on succes.
 *
 * Create a new key set populated with keys from a MIT keytab data
 * structure read from a file.
 *
 * The format of keytab's is proprietary, and this function support
 * the 0x0501 and 0x0502 formats.  See the section The MIT Kerberos
 * Keytab Binary File Format in the Shishi manual for a description of
 * the reverse-engineered format.
 *
 * Returns: Returns %SHISHI_IO_ERROR if the file cannot be read,
 *   %SHISHI_KEYTAB_ERROR if the data cannot be parsed as a valid keytab
 *   structure, and %SHISHI_OK on success.
 **/
int
shishi_keys_from_keytab_file (Shishi * handle,
			      const char *filename,
			      Shishi_keys **outkeys)
{
  int rc;

  rc = shishi_keys (handle, outkeys);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_keys_add_keytab_file (handle, filename, *outkeys);
  if (rc != SHISHI_OK)
    {
      shishi_keys_done (outkeys);
      return rc;
    }

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
