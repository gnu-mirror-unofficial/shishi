/* realm.c	realm related functions
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

/**
 * shishi_realm_default_guess:
 *
 * Guesses a realm based on getdomainname() (which really is NIS/YP
 * domain, but if it is set it might be a good guess), or if it fails,
 * based on gethostname(), or if it fails, the string
 * "could-not-guess-default-realm". Note that the hostname is not
 * trimmed off of the data returned by gethostname() to get the domain
 * name and use that as the realm.
 *
 * Return value: Returns guessed realm for host as a string that has
 * to be deallocated with free() by the caller.
 **/
char *
shishi_realm_default_guess (void)
{
  char buf[HOST_NAME_MAX];
  int ret;

  ret = getdomainname (buf, sizeof (buf));
  buf[sizeof (buf) - 1] = '\0';
  if (ret != 0 || strlen (buf) == 0 || strcmp (buf, "(none)") == 0)
    {
      ret = gethostname (buf, sizeof (buf));
      buf[sizeof (buf) - 1] = '\0';

      if (ret != 0)
	strcpy (buf, "could-not-guess-default-realm");
    }

  return strdup (buf);
}

/**
 * shishi_realm_default:
 * @handle: Shishi library handle create by shishi_init().
 *
 * Return value: Returns the default realm used in the library.  (Not
 * a copy of it, so don't modify or deallocate it.)
 **/
const char *
shishi_realm_default (Shishi * handle)
{
  if (!handle->default_realm)
    {
      char *p;
      p = shishi_realm_default_guess ();
      shishi_realm_default_set (handle, p);
      free (p);
    }

  return handle->default_realm;
}

/**
 * shishi_realm_default_set:
 * @handle: Shishi library handle create by shishi_init().
 * @realm: string with new default realm name, or NULL to reset to default.
 *
 * Set the default realm used in the library.  The string is copied
 * into the library, so you can dispose of the variable immediately
 * after calling this function.
 **/
void
shishi_realm_default_set (Shishi * handle, const char *realm)
{
  if (handle->default_realm)
    free (handle->default_realm);
  if (realm)
    handle->default_realm = strdup (realm);
  else
    handle->default_realm = NULL;
}

const char *
shishi_realm_for_server_file (Shishi * handle, char *server)
{
  return NULL;
}

const char *
shishi_realm_for_server_dns (Shishi * handle, char *server)
{
  const char *p = "JOSEFSSON.ORG";

  fprintf (stderr,
	   "warning: Assuming server `%s' is in realm `%s'\n"
	   "warning: based on insecure DNS information.\n"
	   "warning: Abort if this appear fruadulent.\n", server, p);

  return p;
}

const char *
shishi_realm_for_server (Shishi * handle, char *server)
{
  const char *p;

  p = shishi_realm_for_server_file (handle, server);
  if (!p)
    p = shishi_realm_for_server_dns (handle, server);

  return p;
}
