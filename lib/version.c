/* version.c --- Version handling.
 * Copyright (C) 2002-2013 Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify it it
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */

#include "internal.h"

/**
 * shishi_check_version:
 * @req_version: Oldest acceptable version, or %NULL.
 *
 * Checks that the installed library version is at least
 * as recent as the one provided in @req_version.
 * The version string is formatted like "1.0.2".
 *
 * Whenever %NULL is passed to this function, the check is
 * suppressed, but the library version is still returned.
 *
 * Return value: Returns the active library version,
 *   or %NULL, should the running library be too old.
 **/
const char *
shishi_check_version (const char *req_version)
{
  if (!req_version || strverscmp (req_version, PACKAGE_VERSION) <= 0)
    return PACKAGE_VERSION;

  return NULL;
}
