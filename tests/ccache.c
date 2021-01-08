/* ccache.c --- Self test MIT ccache file readers.
 * Copyright (C) 2002-2021 Simon Josefsson
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

#define EXPECT 2

void
test (Shishi * handle)
{
  Shishi_tkts *tkts;
  const char *ccache = getenv ("CCACHE1");
  int rc;

  if (!ccache)
    ccache = "ccache1.bin";

  rc = shishi_tkts_from_ccache_file (handle, ccache, &tkts);
  if (rc != SHISHI_OK)
    fail ("shishi_tkts_from_ccache_file() failed (%d)\n", rc);

  if (shishi_tkts_size (tkts) != EXPECT)
    fail ("shishi_tkts_size() failed (%d!=%d)\n",
	  shishi_tkts_size (tkts), EXPECT);

  rc = shishi_tkts_write (tkts, stdout);
  if (rc != SHISHI_OK)
    fail ("shishi_tkts_write() failed (%d)\n", rc);

  rc = shishi_tkts_print (tkts, stdout);
  if (rc != SHISHI_OK)
    fail ("shishi_tkts_print() failed (%d)\n", rc);

  {
    Shishi_tkt *tkt;
    size_t i = 0;
    while ((tkt = shishi_tkts_nth (tkts, i++)) != NULL)
      shishi_tkt_done (tkt);
  }

  shishi_tkts_done (&tkts);
}
