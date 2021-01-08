/* utils.c --- Shishi self tests utilities.
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "utils.h"

const char *program_name = PACKAGE;

int debug = 0;
int error_count = 0;
int break_on_error = 0;

void
fail (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  error_count++;
  if (break_on_error)
    exit (EXIT_FAILURE);
}

void
success (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  if (debug)
    vfprintf (stdout, format, arg_ptr);
  va_end (arg_ptr);
}

void
escapeprint (const char *str, size_t len)
{
  size_t i;

  printf (" (length %zu bytes):\n\t", len);
  for (i = 0; i < len; i++)
    {
      if (((str[i] & 0xFF) >= 'A' && (str[i] & 0xFF) <= 'Z') ||
	  ((str[i] & 0xFF) >= 'a' && (str[i] & 0xFF) <= 'z') ||
	  ((str[i] & 0xFF) >= '0' && (str[i] & 0xFF) <= '9')
	  || (str[i] & 0xFF) == ' ' || (str[i] & 0xFF) == '.')
	printf ("%c", (str[i] & 0xFF));
      else
	printf ("\\x%02X", (str[i] & 0xFF));
      if ((i + 1) % 16 == 0 && (i + 1) < len)
	printf ("'\n\t'");
    }
  printf ("\n");
}

void
hexprint (const char *str, size_t len)
{
  size_t i;

  printf ("\t;; ");
  for (i = 0; i < len; i++)
    {
      printf ("%02x ", (str[i] & 0xFF));
      if ((i + 1) % 8 == 0)
	printf (" ");
      if ((i + 1) % 16 == 0 && i + 1 < len)
	printf ("\n\t;; ");
    }
  printf ("\n");
}

void
binprint (const char *str, size_t len)
{
  size_t i;

  printf ("\t;; ");
  for (i = 0; i < len; i++)
    {
      printf ("%d%d%d%d%d%d%d%d ",
	      (str[i] & 0xFF) & 0x80 ? 1 : 0,
	      (str[i] & 0xFF) & 0x40 ? 1 : 0,
	      (str[i] & 0xFF) & 0x20 ? 1 : 0,
	      (str[i] & 0xFF) & 0x10 ? 1 : 0,
	      (str[i] & 0xFF) & 0x08 ? 1 : 0,
	      (str[i] & 0xFF) & 0x04 ? 1 : 0,
	      (str[i] & 0xFF) & 0x02 ? 1 : 0, (str[i] & 0xFF) & 0x01 ? 1 : 0);
      if ((i + 1) % 3 == 0)
	printf (" ");
      if ((i + 1) % 6 == 0 && i + 1 < len)
	printf ("\n\t;; ");
    }
  printf ("\n");
}

int
main (int argc, char *argv[])
{
  Shishi *handle;

  do
    if (strcmp (argv[argc - 1], "-v") == 0 ||
	strcmp (argv[argc - 1], "--verbose") == 0)
      debug = 1;
    else if (strcmp (argv[argc - 1], "-b") == 0 ||
	     strcmp (argv[argc - 1], "--break-on-error") == 0)
      break_on_error = 1;
    else if (strcmp (argv[argc - 1], "-h") == 0 ||
	     strcmp (argv[argc - 1], "-?") == 0 ||
	     strcmp (argv[argc - 1], "--help") == 0)
      {
	printf ("Usage: %s [-vbh?] [--verbose] [--break-on-error] [--help]\n",
		argv[0]);
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
    {
      shishi_cfg (handle, strdup ("verbose"));
      shishi_cfg (handle, strdup ("verbose-noise"));
      shishi_cfg (handle, strdup ("verbose-asn1"));
      shishi_cfg (handle, strdup ("verbose-crypto"));
      shishi_cfg (handle, strdup ("verbose-crypto-noise"));
    }

  test (handle);

  shishi_done (handle);

  if (debug)
    printf ("Self test `%s' finished with %d errors\n", argv[0], error_count);

  return error_count ? 1 : 0;
}
