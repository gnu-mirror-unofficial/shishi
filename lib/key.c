/* key.c	Key related functions.
 * Copyright (C) 2002  Simon Josefsson
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

struct Shishi_key
{
  Shishi *handle;
  char *principal;
  char *realm;
  int type;
  char value[MAX_KEY_LEN];
  int version;
};

/**
 * shishi_key_principal:
 * @key: structure that holds key information
 *
 * Return value: Returns the principal owning the key.  (Not a copy of
 * it, so don't modify or deallocate it.)
 **/
const char *
shishi_key_principal (Shishi_key * key)
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
    key->principal = strdup(principal);
  else
    key->principal = NULL;
}

/**
 * shishi_key_realm:
 * @key: structure that holds key information
 *
 * Return value: Returns the realm for the principal owning the key.
 * (Not a copy of it, so don't modify or deallocate it.)
 **/
const char *
shishi_key_realm (Shishi_key * key)
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
    key->realm = strdup(realm);
  else
    key->realm = NULL;
}

/**
 * shishi_key_type:
 * @key: structure that holds key information
 *
 * Return value: Returns the type of key as an integer as described in
 * the standard.
 **/
int
shishi_key_type (Shishi_key * key)
{
  return key->type;
}

/**
 * shishi_key_type_set:
 * @key: structure that holds key information
 *
 * Set the type of key in key structure.
 **/
void
shishi_key_type_set (Shishi_key * key, int type)
{
  key->type = type;
}

/**
 * shishi_key_value:
 * @key: structure that holds key information
 *
 * Return value: Returns the key value as a pointer which is valid
 * throughout the lifetime of the key structure.
 **/
char *
shishi_key_value (Shishi_key * key)
{
  return key->value;
}

/**
 * shishi_key_value_set:
 * @key: structure that holds key information
 * @value: input array with key data.
 * @length: length of input array with key data.
 *
 * Set the key value and length in key structure.
 **/
void
shishi_key_value_set (Shishi_key * key, char *value)
{
  if (value &&
      shishi_cipher_keylen (key->type) > 0 &&
      shishi_cipher_keylen (key->type) <= MAX_KEY_LEN)
    memcpy(key->value, value, shishi_cipher_keylen (key->type));
}

/**
 * shishi_key_version:
 * @key: structure that holds key information
 *
 * Return value: Returns the version of key ("kvno").
 **/
int
shishi_key_version (Shishi_key * key)
{
  return key->version;
}

/**
 * shishi_key_version_set:
 * @key: structure that holds key information
 * @version: new version integer.
 *
 * Set the version of key ("kvno") in key structure.
 **/
void
shishi_key_version_set (Shishi_key * key, int version)
{
  key->version = version;
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
  return shishi_cipher_name(key->type);
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
shishi_key_length (Shishi_key * key)
{
  return shishi_cipher_keylen(key->type);
}

/**
 * shishi_key:
 * @handle: Shishi library handle create by shishi_init().
 * @key: pointer to structure that will hold newly created key information
 *
 * Create a new Key information structure.
 *
 * Return value: Returns SHISHI_MALLOC_ERROR on memory allocation
 *               errors, and SHISHI_OK on success.
 **/
int
shishi_key (Shishi *handle, Shishi_key **key)
{
  *key = malloc (sizeof (**key));
  if (!*key)
    return SHISHI_MALLOC_ERROR;
  memset(*key, 0, sizeof(**key));

  (*key)->handle = handle;

  return SHISHI_OK;
}

/**
 * shishi_key_done:
 * @key: pointer to structure that holds key information.
 *
 * Deallocates key information structure and set key handle to NULL.
 **/
void
shishi_key_done (Shishi_key **key)
{
  free(*key);
  *key = NULL;
}

/**
 * shishi_key_copy:
 * @dstkey: structure that holds destination key information
 * @srckey: structure that holds source key information
 *
 * Copies source key into existing allocated destination key.
 **/
void
shishi_key_copy (Shishi_key * dstkey, Shishi_key *srckey)
{
  shishi_key_type_set(dstkey, shishi_key_type(srckey));
  shishi_key_value_set(dstkey, shishi_key_value(srckey));
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
 * Return value: Returns SHISHI_MALLOC_ERROR on memory allocation
 *               errors, and SHISHI_OK on success.
 **/
int
shishi_key_from_value (Shishi *handle,
		       int type,
		       char *value,
		       Shishi_key **key)
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
 * Return value: Returns SHISHI_MALLOC_ERROR on memory allocation
 *               errors, SHISHI_INVALID_KEY if the base64 encoded key
 *               length doesn't match the key type, and SHISHI_OK on
 *               success.
 **/
int
shishi_key_from_base64 (Shishi *handle,
			int type,
			char *value,
			Shishi_key **key)
{
  int rc;

  rc = shishi_key (handle, key);
  if (rc != SHISHI_OK)
    return rc;

  shishi_key_type_set (*key, type);

  if (value)
    {
      int len;
      char *buf;

      buf = malloc(strlen(value) + 1);
      if (!buf)
	return SHISHI_MALLOC_ERROR;

      len = shishi_from_base64 (buf, value);

      if (len != shishi_key_length(*key))
	{
	  free(buf);
	  return SHISHI_INVALID_KEY;
	}

      shishi_key_value_set (*key, buf);

      free(buf);
    }

  return SHISHI_OK;
}

/**
 * shishi_key_from_random
 * @handle: Shishi library handle create by shishi_init().
 * @type: type of key.
 * @random: random data.
 * @randomlen: length of random data.
 *
 * Create a new Key information structure, and set the key type and
 * key value using shishi_random_to_key().  KEY contains a newly
 * allocated structure only if this function is successful.
 *
 * Return value: Returns SHISHI_MALLOC_ERROR on memory allocation
 *               errors, and SHISHI_OK on success.
 **/
int
shishi_key_from_random (Shishi *handle,
			int type,
			char *random,
			int randomlen,
			Shishi_key **key)
{
  int rc;

  rc = shishi_key (handle, key);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_random_to_key (handle, type, random, randomlen, *key);

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
 *
 * Create a new Key information structure, and set the key type and
 * key value using shishi_string_to_key().  KEY contains a newly
 * allocated structure only if this function is successful.
 *
 * Return value: Returns SHISHI_MALLOC_ERROR on memory allocation
 *               errors, and SHISHI_OK on success.
 **/
int
shishi_key_from_string (Shishi *handle,
			int type,
			char *password,
			int passwordlen,
			char *salt,
			int saltlen,
			char *parameter,
			Shishi_key **key)
{
  int rc;

  rc = shishi_key (handle, key);
  if (rc != SHISHI_OK)
    return rc;

  rc = shishi_string_to_key (handle, type, password, passwordlen,
			     salt, saltlen, parameter, *key);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}
