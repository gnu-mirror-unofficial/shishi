/* gss.c	Shishi GSS-API self tests.
 * Copyright (C) 2003  Simon Josefsson
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
#include <shishi/gssapi.h>

int
main (int argc, char *argv[])
{
  char buffer[BUFSIZ];
  char buffer2[BUFSIZ];
  char *p, *q;
  int n, res;
  gss_uint32 maj_stat, min_stat;
  gss_buffer_desc bufdesc, bufdesc2;
  gss_name_t service;

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

  escapeprint (NULL, 0);
  hexprint (NULL, 0);
  binprint (NULL, 0);

  service = NULL;
  bufdesc.value = "imap@server.example.org@FOO";
  bufdesc.length = strlen(bufdesc.value);

  maj_stat = gss_import_name (&min_stat, &bufdesc, GSS_C_NT_HOSTBASED_SERVICE,
			      &service);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_import_name() OK\n");
  else
    fail("gss_import_name() failed (%d,%d)\n", maj_stat, min_stat);

  maj_stat = gss_display_name (&min_stat, service, &bufdesc2, NULL);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_display_name() OK\n");
  else
    fail("gss_display_name() failed (%d,%d)\n", maj_stat, min_stat);

  if (debug)
    printf("display_name() => %d: %s\n", bufdesc2.length, bufdesc2.value);

  if (verbose)
    printf ("Ticket set self tests done with %d errors\n", error_count);

  return error_count ? 1 : 0;
}
