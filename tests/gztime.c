/* gztime.c	Shishi generalized time self tests.
 * Copyright (C) 2002, 2003  Simon Josefsson
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

#include "utils.c"

void
test (Shishi * handle)
{
  const char *p;
  int n;

  /* shishi_authenticator_ctime_set() */
  p = shishi_generalize_time (handle, (time_t) 4711);
  if (debug)
    escapeprint (p, 15);
  if (p && memcmp (p, "19700101011831Z", 15) == 0)
    success ("shishi_generalize_time() OK\n");
  else
    fail ("shishi_generalize_time() failed\n");

  /* shishi_generalize_ctime() */
  n = (int) shishi_generalize_ctime (handle, p);
  if (debug)
    printf ("shishi_generalize_ctime () => `%d'.\n", n);
  if (n == 4711)
    success ("shishi_generalize_ctime() OK\n");
  else
    fail ("shishi_generalize_ctime() failed\n");
}
