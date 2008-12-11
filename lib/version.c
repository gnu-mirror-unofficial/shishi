/* version.c --- Version handling.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008  Simon Josefsson
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
 * @req_version: version string to compare with, or NULL
 *
 * Check that the the version of the library is at minimum the one
 * given as a string in @req_version.
 *
 * Return value: the actual version string of the library; NULL if the
 *   condition is not met.  If %NULL is passed to this function no
 *   check is done and only the version string is returned.
 **/
const char *
shishi_check_version (const char *req_version)
{
  if (!req_version || strverscmp (req_version, PACKAGE_VERSION) <= 0)
    return PACKAGE_VERSION;

  return NULL;
}
