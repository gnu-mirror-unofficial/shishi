/* hostkeys.c --- Functions for managing hostkeys stored in files.
 * Copyright (C) 2002, 2003, 2004, 2007  Simon Josefsson
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

/**
 * shishi_hostkeys_default_file:
 * @handle: Shishi library handle create by shishi_init().
 *
 * Get file name of default host key file.
 *
 * Return value: Returns the default host key filename used in the
 * library.  (Not a copy of it, so don't modify or deallocate it.)
 **/
const char *
shishi_hostkeys_default_file (Shishi * handle)
{
  char *envfile;

  envfile = getenv ("SHISHI_KEYS");
  if (envfile)
    shishi_hostkeys_default_file_set (handle, envfile);

  if (!handle->hostkeysdefaultfile)
    handle->hostkeysdefaultfile = xstrdup (HOSTKEYSFILE);

  return handle->hostkeysdefaultfile;
}

/**
 * shishi_hostkeys_default_file_set:
 * @handle: Shishi library handle create by shishi_init().
 * @hostkeysfile: string with new default hostkeys file name, or
 *                NULL to reset to default.
 *
 * Set the default host key filename used in the library.  The
 * string is copied into the library, so you can dispose of the
 * variable immediately after calling this function.
 **/
void
shishi_hostkeys_default_file_set (Shishi * handle, const char *hostkeysfile)
{
  if (handle->hostkeysdefaultfile)
    free (handle->hostkeysdefaultfile);
  if (hostkeysfile)
    handle->hostkeysdefaultfile = xstrdup (hostkeysfile);
  else
    handle->hostkeysdefaultfile = NULL;
}

/**
 * shishi_hostkeys_for_server
 * @handle: Shishi library handle create by shishi_init().
 * @server: server name to get key for
 *
 * Get host key for @server.
 *
 * Return value: Returns the key for specific server, read from the
 * default host keys file (see shishi_hostkeys_default_file()), or
 * NULL if no key could be found or an error encountered.
 **/
Shishi_key *
shishi_hostkeys_for_server (Shishi * handle, const char *server)
{
  return shishi_keys_for_server_in_file (handle,
					 shishi_hostkeys_default_file
					 (handle), server);
}

/**
 * shishi_hostkeys_for_serverrealm
 * @handle: Shishi library handle create by shishi_init().
 * @server: server name to get key for
 * @realm: realm of server to get key for.
 *
 * Get host key for @server in @realm.
 *
 * Return value: Returns the key for specific server and realm, read
 * from the default host keys file (see
 * shishi_hostkeys_default_file()), or NULL if no key could be found
 * or an error encountered.
 **/
Shishi_key *
shishi_hostkeys_for_serverrealm (Shishi * handle,
				 const char *server, const char *realm)
{
  return shishi_keys_for_serverrealm_in_file
    (handle, shishi_hostkeys_default_file (handle), server, realm);
}

/**
 * shishi_hostkeys_for_localservicerealm
 * @handle: Shishi library handle create by shishi_init().
 * @service: service to get key for.
 * @realm: realm of server to get key for, or NULL for default realm.
 *
 * Get host key for @service on current host in @realm.
 *
 * Return value: Returns the key for the server
 * "SERVICE/HOSTNAME@REALM" (where HOSTNAME is the current system's
 * hostname), read from the default host keys file (see
 * shishi_hostkeys_default_file()), or NULL if no key could be found
 * or an error encountered.
 **/
Shishi_key *
shishi_hostkeys_for_localservicerealm (Shishi * handle,
				       const char *service, const char *realm)
{
  return shishi_keys_for_localservicerealm_in_file
    (handle, shishi_hostkeys_default_file (handle), service, realm);
}

/**
 * shishi_hostkeys_for_localservice
 * @handle: Shishi library handle create by shishi_init().
 * @service: service to get key for.
 *
 * Get host key for @service on current host in default realm.
 *
 * Return value: Returns the key for the server "SERVICE/HOSTNAME"
 * (where HOSTNAME is the current system's hostname), read from the
 * default host keys file (see shishi_hostkeys_default_file()), or
 * NULL if no key could be found or an error encountered.
 **/
Shishi_key *
shishi_hostkeys_for_localservice (Shishi * handle, const char *service)
{
  return shishi_hostkeys_for_localservicerealm (handle, service, NULL);
}
