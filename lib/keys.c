/* keys.c	Functions for managing keys stored in files.
 * Copyright (C) 2002, 2003  Simon Josefsson
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
 * shishi_keys_for_serverrealm_in_file
 * @handle: Shishi library handle create by shishi_init().
 * @filename: file to read keys from.
 * @server: server name to get key for.
 * @realm: realm of server to get key for.
 *
 * Return value: Returns the key for specific server and realm, read
 * from the indicated file, or NULL if no key could be found or an
 * error encountered.
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

      if (VERBOSENOICE (handle))
	{
	  printf ("Read key:\n");
	  shishi_key_print (handle, stdout, key);
	}

      if (server == NULL && realm == NULL)
	break;

      if (server &&
	  shishi_key_principal (key) &&
	  strcmp (server, shishi_key_principal (key)) == 0)
	break;

      if (realm &&
	  shishi_key_realm (key) &&
	  strcmp (server, shishi_key_principal (key)) == 0)
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
 * Return value: Returns the key for specific server, read from the
 * indicated file, or NULL if no key could be found or an error
 * encountered.
 **/
Shishi_key *
shishi_keys_for_server_in_file (Shishi * handle,
				const char *filename, const char *server)
{
  return shishi_keys_for_serverrealm_in_file (handle, filename, server, NULL);
}

/**
 * shishi_keys_for_localservice_in_file
 * @handle: Shishi library handle create by shishi_init().
 * @filename: file to read keys from.
 * @service: service to get key for.
 * @realm: realm of server to get key for, or NULL for default realm.
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
  char server[HOST_NAME_MAX];
  int ret;

  strcpy (server, service);
  strcat (server, "/");

  ret = gethostname (&server[strlen (service) + 1],
		     sizeof (server) - strlen (service) - 1);
  server[sizeof (server) - 1] = '\0';

  if (ret != 0)
    strcpy (&server[strlen (service) + 1], "localhost");

  return shishi_keys_for_serverrealm_in_file (handle, filename, server,
					      realm);
}
