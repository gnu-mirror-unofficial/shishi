/* keytab.c --- Self test MIT keytab file readers.
 * Copyright (C) 2002, 2003, 2006, 2007, 2008  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#include "utils.c"

void
test (Shishi * handle)
{
  Shishi_keys *keys;
  const char *keytab = getenv ("KEYTAB1");
  int rc;

  if (!keytab)
    keytab = "keytab1.bin";

  rc = shishi_keys_from_keytab_file (handle, keytab, &keys);
  if (rc != SHISHI_OK)
    fail ("shishi_keys_from_keytab_file() failed (%d)\n", rc);

  if (shishi_keys_size (keys) != 6)
    fail ("shishi_keys_size() failed (%d)\n", shishi_keys_size (keys));

  shishi_keys_done (&keys);
}
