/* principal.c	get and set default principal
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
 * shishi_principal_default_guess:
 *
 * Guesses a principal using getpwuid(getuid)), or if it fails, the
 * string "user".
 *
 * Return value: Returns guessed default principal for user as a string that
 * has to be deallocated with free() by the caller.
 **/
char *
shishi_principal_default_guess (void)
{
  uid_t uid;
  struct passwd *pw;

  uid = getuid ();
  pw = getpwuid (uid);

  if (pw)
    return strdup (pw->pw_name);
  else
    return strdup ("user");
}


/**
 * shishi_principal_default:
 * @handle: Shishi library handle create by shishi_init().
 *
 * Return value: Returns the default principal name used in the
 * library.  (Not a copy of it, so don't modify or deallocate it.)
 **/
const char *
shishi_principal_default (Shishi * handle)
{
  if (!handle->default_principal)
    {
      char *p;
      p = shishi_principal_default_guess ();
      shishi_principal_default_set (handle, p);
      free (p);
    }

  return handle->default_principal;
}

/**
 * shishi_principal_default_set:
 * @handle: Shishi library handle create by shishi_init().
 * @principal: string with new default principal name, or NULL to
 * reset to default.
 *
 * Set the default realm used in the library.  The string is copied
 * into the library, so you can dispose of the variable immediately
 * after calling this function.
 **/
void
shishi_principal_default_set (Shishi * handle, const char *principal)
{
  if (handle->default_principal)
    free (handle->default_principal);
  if (principal)
    handle->default_principal = strdup (principal);
  else
    handle->default_principal = NULL;
}
