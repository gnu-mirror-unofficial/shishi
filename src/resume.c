/* resume.c --- Handle the details of TLS session resumption.
 * Copyright (C) 2002, 2003, 2007  Simon Josefsson
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

/* Note: only use syslog to report errors in this file. */

/* Get Shishid stuff. */
#include "kdc.h"

typedef struct
{
  char *id;
  size_t id_size;
  char *data;
  size_t data_size;
} CACHE;

static CACHE *cache_db;
static size_t cache_db_ptr = 0;
static size_t cache_db_size = 0;

int
resume_db_store (void *dbf, gnutls_datum key, gnutls_datum data)
{
  if (cache_db_size == 0)
    return -1;

  cache_db[cache_db_ptr].id = xrealloc (cache_db[cache_db_ptr].id, key.size);
  memcpy (cache_db[cache_db_ptr].id, key.data, key.size);
  cache_db[cache_db_ptr].id_size = key.size;

  cache_db[cache_db_ptr].data = xrealloc (cache_db[cache_db_ptr].data,
					  data.size);
  memcpy (cache_db[cache_db_ptr].data, data.data, data.size);
  cache_db[cache_db_ptr].data_size = data.size;

  cache_db_ptr++;
  cache_db_ptr %= cache_db_size;

  return 0;
}

gnutls_datum
resume_db_fetch (void *dbf, gnutls_datum key)
{
  gnutls_datum res = { NULL, 0 };
  size_t i;

  for (i = 0; i < cache_db_size; i++)
    if (key.size == cache_db[i].id_size &&
	memcmp (key.data, cache_db[i].id, key.size) == 0)
      {
	res.size = cache_db[i].data_size;

	res.data = gnutls_malloc (res.size);
	if (res.data == NULL)
	  return res;

	memcpy (res.data, cache_db[i].data, res.size);

	return res;
      }

  return res;
}

int
resume_db_delete (void *dbf, gnutls_datum key)
{
  size_t i;

  for (i = 0; i < cache_db_size; i++)
    if (key.size == cache_db[i].id_size &&
	memcmp (key.data, cache_db[i].id, key.size) == 0)
      {
	cache_db[i].id_size = 0;
	cache_db[i].data_size = 0;

	return 0;
      }

  return -1;
}

void
resume_db_init (size_t nconnections)
{
  resume_db_done ();
  cache_db = xcalloc (nconnections, sizeof (*cache_db));
  cache_db_size = nconnections;
}

void
resume_db_done (void)
{
  size_t i;

  for (i = 0; i < cache_db_size; i++)
    {
      if (cache_db[i].id)
	free (cache_db[i].id);
      if (cache_db[i].data)
	free (cache_db[i].data);
    }

  if (cache_db)
    free (cache_db);
}
