/* db.c --- Abstract interface to a kerberos database backend.
 * Copyright (C) 2003  Simon Josefsson
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

/* Get "file" database prototypes. */
#include "file.h"

static _Shisa_backend _shisa_backends[] = {
  {"file",
   shisa_file_init,
   shisa_file_done,
   shisa_file_enumerate_realms,
   shisa_file_enumerate_principals,
   shisa_file_principal_find,
   shisa_file_principal_update,
   shisa_file_principal_add,
   shisa_file_principal_remove,
   shisa_file_keys_find,
   shisa_file_key_add,
   shisa_file_key_update,
   shisa_file_key_remove}
};

_Shisa_backend *
_shisa_find_backend (const char *name)
{
  size_t i;
  for (i = 0; i < sizeof (_shisa_backends) / sizeof (_shisa_backends[0]); i++)
    if (strcmp (name, _shisa_backends[i].name) == 0)
      return &_shisa_backends[i];

  return NULL;
}
