/* realm.c	realm related functions
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

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX BUFSIZ
#endif

char *
shishi_realm_default_guess ()
{
  int ret;
  char *tmp, *tmp2;
  struct hostent *he;

  /* XXX: how to call gethostname() without using fixed size arrays? */

  tmp = (char *) malloc (HOST_NAME_MAX);
  ret = gethostname (tmp, HOST_NAME_MAX);
  tmp[HOST_NAME_MAX - 1] = '\0';
  if (ret != 0)
    {
      strcpy (tmp, "localhost");
    }
  he = gethostbyname (tmp);
  if (he)
    {
      free (tmp);
      tmp = strdup (he->h_name);
    }

  return tmp;

  /*
     if (ret == 0)
     {
     char *p = (char*) strchr (tmp, '.');
     if (p != NULL && *p != '\0')
     {
     p++; / * skip '.' * /
     if (*p != '\0')
     memmove (tmp, p, strlen(p) + 1);
     }
     } 
     else
     {
     tmp = (char*) strdup("unknown");
     }

     tmp2 = tmp;
     while (tmp2 && *tmp2)
     {
     *tmp2 = toupper(*tmp2);
     tmp2++;
     }
   */

  return tmp;
}


void
shishi_realm_default_set (Shishi * handle, const char *realm)
{
  handle->default_realm = (char *) strdup (realm);
}

char *
shishi_realm_default_get (Shishi * handle)
{
  return handle->default_realm;
}
