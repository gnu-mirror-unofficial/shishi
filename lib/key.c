/* key.c --- Key related functions.
 * Copyright (C) 2002, 2003, 2004, 2006, 2007, 2008  Simon Josefsson
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

struct Shishi_key
{
  Shishi *handle;
  char *principal;
  char *realm;
  int type;
  char value[MAX_KEY_LEN];
  uint32_t kvno; /* UINT32_MAX means undefined kvno */
};

/**
 * shishi_key_principal:
 * @key: structure that holds key information
 *
 * Get the principal part of the key owner principal name, i.e.,
 * except the realm.
 *
 * Return value: Returns the principal owning the key.  (Not a copy of
 * it, so don't modify or deallocate it.)
 **/
const char *
shishi_key_principal (const Shishi_key * key)
{
  return key->principal;
}

/**
 * shishi_key_principal_set:
 * @key: structure that holds key information
 * @principal: string with new principal name.
 *
 * Set the principal owning the key. The string is copied into the
 * key, so you can dispose of the variable immediately after calling
 * this function.
 **/
void
shishi_key_principal_set (Shishi_key * key, const char *principal)
{
  if (key->principal)
    free (key->principal);
  if (principal)
    key->principal = xstrdup (principal);
  else
    key->principal = NULL;
}

/**
 * shishi_key_realm:
 * @key: structure that holds key information
 *
 * Get the realm part of the key owner principal name.
 *
 * Return value: Returns the realm for the principal owning the key.
 * (Not a copy of it, so don't modify or deallocate it.)
 **/
const char *
shishi_key_realm (const Shishi_key * key)
{
  return key->realm;
}

/**
 * shishi_key_realm_set:
 * @key: structure that holds key information
 * @realm: string with new realm name.
 *
 * Set the realm for the principal owning the key. The string is
 * copied into the key, so you can dispose of the variable immediately
 * after calling this function.
 **/
void
shishi_key_realm_set (Shishi_key * key, const char *realm)
{
  if (key->realm)
    free (key->realm);
  if (realm)
    key->realm = xstrdup (realm);
  else
    key->realm = NULL;
}

/**
 * shishi_key_type:
 * @key: structure that holds key information
 *
 * Get key type.
 *
 * Return value: Returns the type of key as an integer as described in
 * the standard.
 **/
int
shishi_key_type (const Shishi_key * key)
{
  return key->type;
}

/**
 * shishi_key_type_set:
 * @key: structure that holds key information
 * @type: type to set in key.
 *
 * Set the type of key in key structure.
 **/
void
shishi_key_type_set (Shishi_key * key, int32_t type)
{
  key->type = type;
}

/**
 * shishi_key_value:
 * @key: structure that holds key information
 *
 * Get the raw key bytes.
 *
 * Return value: Returns the key value as a pointer which is valid
 * throughout the lifetime of the key structure.
 **/
const char *
shishi_key_value (const Shishi_key * key)
{
  return key->value;
}

/**
 * shishi_key_value_set:
 * @key: structure that holds key information
 * @value: input array with key data.
 *
 * Set the key value and length in key structure.  The value is copied
 * into the key (in other words, you can deallocate @value right after
 * calling this function without modifying the value inside the key).
 **/
void
shishi_key_value_set (Shishi_key * key, const char *value)
{
  if (value &&
      shishi_cipher_keylen (key->type) > 0 &&
      shishi_cipher_keylen (key->type) <= MAX_KEY_LEN)
    memcpy (key->value, value, shishi_cipher_keylen (key->type));
}

/**
 * shishi_key_version:
 * @key: structure that holds key information
 *
 * Get the "kvno" (key version) of key.  It will be UINT32_MAX if the
 * key is not long-lived.
 *
 * Return value: Returns the version of key ("kvno").
 **/
uint32_t
shishi_key_version (const Shishi_key * key)
{
  return key->kvno;
}

/**
 * shishi_key_version_set:
 * @key: structure that holds key information
 * @kvno: new version integer.
 *
 * Set the version of key ("kvno") in key structure.  Use UINT32_MAX
 * for non-ptermanent keys.
 **/
void
shishi_key_version_set (Shishi_key * key, uint32_t kvno)
{
  key->kvno = kvno;
}

/**
 * shishi_key_name:
 * @key: structure that holds key information
 *
 * Calls shishi_cipher_name for key type.
 *
 * Return value: Return name of key.
 **/
const char *
shishi_key_name (Shishi_key * key)
{
  return shishi_cipher_name (key->type);
}

/**
 * shishi_key_length:
 * @key: structure that holds key information
 *
 * Calls shishi_cipher_keylen for key type.
 *
 * Return value: Returns the length of the key value.
 **/
size_t
shishi_key_length (const Shishi_key * key)
{
  return shishi_cipher_keylen (key->type);
}

/**
 * shishi_key:
 * @handle: Shishi library handle create by shishi_init().
 * @key: pointer to structure that will hold newly created key information
 *
 * Create a new Key information structure.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_key (Shishi * handle, Shishi_key ** key)
{
  *key = xcalloc (1, sizeof (**key));

  (*key)->handle = handle;
  (*key)->kvno = UINT32_MAX;

  return SHISHI_OK;
}

/**
 * shishi_key_done:
 * @key: pointer to structure that holds key information.
 *
 * Deallocates key information structure.
 **/
void
shishi_key_done (Shishi_key * key)
{
  if (key->realm)
    free (key->realm);
  if (key->principal)
    free (key->principal);
  free (key);
}

/**
 * shishi_key_copy:
 * @dstkey: structure that holds destination key information
 * @srckey: structure that holds source key information
 *
 * Copies source key into existing allocated destination key.
 **/
void
shishi_key_copy (Shishi_key * dstkey, Shishi_key * srckey)
{
  shishi_key_principal_set (dstkey, shishi_key_principal (srckey));
  shishi_key_realm_set (dstkey, shishi_key_realm (srckey));
  shishi_key_type_set (dstkey, shishi_key_type (srckey));
  shishi_key_value_set (dstkey, shishi_key_value (srckey));
  shishi_key_version_set (dstkey, shishi_key_version (srckey));
}

/**
 * shishi_key_from_value:
 * @handle: Shishi library handle create by shishi_init().
 * @type: type of key.
 * @value: input array with key value, or NULL.
 * @key: pointer to structure that will hold newly created key information
 *
 * Create a new Key information structure, and set the key type and
 * key value. KEY contains a newly allocated structure only if this
 * function is successful.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_key_from_value (Shishi * handle,
		       int32_t type, const char *value, Shishi_key ** key)
{
  int rc;

  rc = shishi_key (handle, key);
  if (rc != SHISHI_OK)
    return rc;

  shishi_key_type_set (*key, type);
  if (value)
    shishi_key_value_set (*key, value);

  return SHISHI_OK;
}

/**
 * shishi_key_from_base64:
 * @handle: Shishi library handle create by shishi_init().
 * @type: type of key.
 * @value: input string with base64 encoded key value, or NULL.
 * @key: pointer to structure that will hold newly created key information
 *
 * Create a new Key information structure, and set the key type and
 * key value. KEY contains a newly allocated structure only if this
 * function is successful.
 *
 * Return value: Returns SHISHI_INVALID_KEY if the base64 encoded key
 *               length doesn't match the key type, and SHISHI_OK on
 *               success.
 **/
int
shishi_key_from_base64 (Shishi * handle,
			int32_t type, const char *value, Shishi_key ** key)
{
  int rc;

  rc = shishi_key (handle, key);
  if (rc != SHISHI_OK)
    return rc;

  shishi_key_type_set (*key, type);

  if (value)
    {
      size_t len = MAX_KEY_LEN;

      if (!base64_decode (value, strlen (value), (*key)->value, &len))
	{
	  shishi_key_done (*key);
	  return SHISHI_BASE64_ERROR;
	}

      if (len != shishi_key_length (*key))
	{
	  shishi_key_done (*key);
	  return SHISHI_INVALID_KEY;
	}
    }

  return SHISHI_OK;
}

/**
 * shishi_key_random
 * @handle: Shishi library handle create by shishi_init().
 * @type: type of key.
 * @key: pointer to structure that will hold newly created key information
 *
 * Create a new Key information structure for the key type and some
 * random data.  KEY contains a newly allocated structure only if this
 * function is successful.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_key_random (Shishi * handle, int32_t type, Shishi_key ** key)
{
  char buf[MAX_RANDOM_LEN];
  int len = shishi_cipher_randomlen (type);
  int rc;

  rc = shishi_randomize (handle, 1, buf, len);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_key (handle, key);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_random_to_key (handle, type, buf, len, *key);
  if (rc != SHISHI_OK)
    {
      shishi_key_done (*key);
      return rc;
    }

  return SHISHI_OK;
}

/**
 * shishi_key_from_random
 * @handle: Shishi library handle create by shishi_init().
 * @type: type of key.
 * @rnd: random data.
 * @rndlen: length of random data.
 * @outkey: pointer to structure that will hold newly created key information
 *
 * Create a new Key information structure, and set the key type and
 * key value using shishi_random_to_key().  KEY contains a newly
 * allocated structure only if this function is successful.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_key_from_random (Shishi * handle,
			int32_t type,
			const char *rnd, size_t rndlen, Shishi_key ** outkey)
{
  int rc;

  rc = shishi_key (handle, outkey);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_random_to_key (handle, type, rnd, rndlen, *outkey);

  return rc;
}

/**
 * shishi_key_from_string
 * @handle: Shishi library handle create by shishi_init().
 * @type: type of key.
 * @password: input array containing password.
 * @passwordlen: length of input array containing password.
 * @salt: input array containing salt.
 * @saltlen: length of input array containing salt.
 * @parameter: input array with opaque encryption type specific information.
 * @outkey: pointer to structure that will hold newly created key information
 *
 * Create a new Key information structure, and set the key type and
 * key value using shishi_string_to_key().  KEY contains a newly
 * allocated structure only if this function is successful.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_key_from_string (Shishi * handle,
			int32_t type,
			const char *password, size_t passwordlen,
			const char *salt, size_t saltlen,
			const char *parameter, Shishi_key ** outkey)
{
  int rc;

  rc = shishi_key (handle, outkey);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_string_to_key (handle, type, password, passwordlen,
			     salt, saltlen, parameter, *outkey);
  if (rc != SHISHI_OK)
    {
      shishi_key_done (*outkey);
      return rc;
    }

  return SHISHI_OK;
}

/**
 * shishi_key_from_name:
 * @handle: Shishi library handle create by shishi_init().
 * @type: type of key.
 * @name: principal name of user.
 * @password: input array containing password.
 * @passwordlen: length of input array containing password.
 * @parameter: input array with opaque encryption type specific information.
 * @outkey: pointer to structure that will hold newly created key information
 *
 * Create a new Key information structure, and derive the key from
 * principal name and password using shishi_key_from_name().  The salt
 * is derived from the principal name by concatenating the decoded
 * realm and principal.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_key_from_name (Shishi * handle,
		      int32_t type,
		      const char *name,
		      const char *password, size_t passwordlen,
		      const char *parameter, Shishi_key ** outkey)
{
  int rc;
  char *salt;

  rc = shishi_derive_default_salt (handle, name, &salt);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_key_from_string (handle, type, password, passwordlen,
			       salt, strlen (salt), parameter, outkey);
  if (rc == SHISHI_OK)
    {
      char *principal;
      char *realm;

      rc = shishi_parse_name (handle, name, &principal, &realm);
      if (rc == SHISHI_OK)
	{
	  shishi_key_principal_set (*outkey, principal);
	  shishi_key_realm_set (*outkey, realm);

	  free (realm);
	  free (principal);
	}
    }

  free (salt);

  return rc;
}
