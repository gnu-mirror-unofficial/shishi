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

/**
 * shishi_key_get_type:
 * @key: structure that holds key information
 *
 * Return value: Returns the type of key as an integer as described in
 * the standard.
 **/
int
shishi_key_get_type (Shishi_key * key)
{
  return key->type;
}

/**
 * shishi_key_get_value:
 * @key: structure that holds key information
 *
 * Return value: Returns the key value as a pointer which is valid
 * throughout the lifetime of the key structure.
 **/
char *
shishi_key_get_value (Shishi_key * key)
{
  return key->value;
}

/**
 * shishi_key_get_length:
 * @key: structure that holds key information
 *
 * Return value: Returns length of the key value.
 **/
int
shishi_key_get_length (Shishi_key * key)
{
  return key->length;
}

/**
 * shishi_key:
 * @type: type of key.
 * @value: key value.
 * @length: length of key.
 *
 * Allocates a new key information structure and copies the supplied
 * data into it.
 *
 * Return value: Returns newly allocated key structure, or NULL on failure.
 **/
Shishi_key *
shishi_key (Shishi *handle,
	    int type,
	    char *value,
	    int length)
{
  Shishi_key *key;

  if (length > MAX_KEY_LEN)
    return NULL;

  key = malloc (sizeof (*key));
  if (key)
    {
      key->type = type;
      memcpy(key->value, value, length);
      key->length = length;
    }

  return key;
}
