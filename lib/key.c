/* key.c	Key related functions.
 * Copyright (C) 2002  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with Shishi; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "internal.h"

struct Shishi_key
{
  int type;
  char value[MAX_KEY_LEN];
  int version;
};

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
 * Return value: Returns the version of key.
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
 * Set the version of key in key structure.
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
 * Return value: Returns the length of the key.
 **/
size_t
shishi_key_length (Shishi_key * key)
{
  return shishi_cipher_keylen(key->type);
}

/**
 * shishi_key:
 * @type: type of key.
 * @value: key value.
 *
 * Allocates a new key information structure and copies the supplied
 * data into it.
 *
 * Return value: Returns newly allocated key structure, or NULL on failure.
 **/
Shishi_key *
shishi_key (int type, char *value)
{
  Shishi_key *key;

  key = malloc (sizeof (*key));
  if (!key)
    return NULL;

  shishi_key_type_set (key, type);
  shishi_key_version_set (key, 0);
  if (value)
    shishi_key_value_set (key, value);

  return key;
}

/**
 * shishi_key_done:
 * @key: structure that holds key information
 *
 * Deallocates key information structure.
 **/
void
shishi_key_done (Shishi_key *key)
{
  free(key);
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
 * shishi_key_from_random
 * @type: type of key.
 * @random: random data.
 * @randomlen: length of random data.
 *
 * Allocates a new key information structure and creates key based on
 * random data supplied.  KEY contains a newly allocated structure if
 * succesful.
 *
 * Return value: Returns SHISHI_OK iff succesful.
 **/
int
shishi_key_from_random (Shishi *handle,
			int type,
			char *random,
			int randomlen,
			Shishi_key **outkey)
{
  int res;

  *outkey = shishi_key(type, NULL);

  res = shishi_random_to_key (handle, type, random, randomlen, *outkey);

  return res;
}

/**
 * shishi_key_from_string
 * @type: type of key.
 * @password: password.
 *
 * Allocates a new key information structure and copies the supplied
 * data into it.
 *
 * Return value: Returns newly allocated key structure, or NULL on failure.
 **/
int
shishi_key_from_string (Shishi *handle,
			int type,
			char *password,
			int passwordlen,
			char *salt,
			int saltlen,
			char *parameter,
			Shishi_key **outkey)
{
  int res;

  *outkey = shishi_key(type, NULL);

  res = shishi_string_to_key (handle, type, password, passwordlen,
			      salt, saltlen, parameter, *outkey);

  return res;
}
