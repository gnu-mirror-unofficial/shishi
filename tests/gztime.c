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

int
main (int argc, char *argv[])
{
  Shishi *handle;
  const char *p;
  int n;

  do
    if (strcmp (argv[argc - 1], "-v") == 0 ||
	strcmp (argv[argc - 1], "--verbose") == 0)
      verbose = 1;
    else if (strcmp (argv[argc - 1], "-d") == 0 ||
	     strcmp (argv[argc - 1], "--debug") == 0)
      debug = 1;
    else if (strcmp (argv[argc - 1], "-b") == 0 ||
	     strcmp (argv[argc - 1], "--break-on-error") == 0)
      break_on_error = 1;
    else if (strcmp (argv[argc - 1], "-h") == 0 ||
	     strcmp (argv[argc - 1], "-?") == 0 ||
	     strcmp (argv[argc - 1], "--help") == 0)
      {
	printf ("Usage: %s [-vdbh?] [--verbose] [--debug] "
		"[--break-on-error] [--help]\n", argv[0]);
	return 1;
      }
  while (argc-- > 1);

  handle = shishi ();
  if (handle == NULL)
    {
      fail ("Could not initialize shishi\n");
      return 1;
    }

  if (debug)
    shishi_cfg (handle, strdup ("verbose"));

  escapeprint (NULL, 0);
  hexprint (NULL, 0);
  binprint (NULL, 0);

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

  shishi_done (handle);

  if (verbose)
    printf ("Generalized time self tests done with %d errors\n", error_count);

  return error_count ? 1 : 0;
}
