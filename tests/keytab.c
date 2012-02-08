/* keytab.c --- Self test MIT keytab file readers.
 * Copyright (C) 2002-2012 Simon Josefsson
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
#include "read-file.h"

void
test (Shishi * handle)
{
  Shishi_keys *keys;
  const Shishi_key *key;
  const char *keytab = getenv ("KEYTAB1");
  char *data, *data2;
  size_t len, len2;
  int rc;
  int keyno = 0;

  if (!keytab)
    keytab = "keytab1.bin";

  data = read_binary_file (keytab, &len);
  if (data == NULL)
    fail ("cannot read keytab file %s", keytab);

  rc = shishi_keys_from_keytab_mem (handle, data, len, &keys);
  if (rc != SHISHI_OK)
    fail ("shishi_keys_from_keytab_mem() failed (%d)\n", rc);

  if (shishi_keys_size (keys) != 6)
    fail ("shishi_keys_size() failed (%d)\n", shishi_keys_size (keys));

  if (debug)
    {
      while ((key = shishi_keys_nth (keys, keyno++)) != NULL)
	{
	  rc = shishi_key_print (handle, stdout, key);
	  if (rc != SHISHI_OK)
	    fail ("shishi_key_print() failed (%d)\n", rc);
	}
    }

  rc = shishi_keys_to_keytab_mem (handle, keys, &data2, &len2);
  if (rc != SHISHI_OK)
    fail ("shishi_keys_to_keytab_mem() failed (%d)\n", rc);

  if (len != len2 || memcmp (data, data2, len) != 0)
    fail ("memory comparison failed\n");

  shishi_keys_done (&keys);
  free (data);
  free (data2);
}
