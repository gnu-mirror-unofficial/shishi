/* principal.c	get and set default principal
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

char *
shishi_principal_default_guess ()
{
  uid_t uid;
  struct passwd *pw;

  uid = getuid ();
  pw = getpwuid (uid);

  if (pw)
    return strdup (pw->pw_name);
  else
    return NULL;
}


void
shishi_principal_default_set (Shishi * handle, const char *principal)
{
  handle->default_principal = (char *) strdup (principal);
}

char *
shishi_principal_default_get (Shishi * handle)
{
  return handle->default_principal;
}
