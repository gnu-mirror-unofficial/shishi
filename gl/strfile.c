/* strfile.c -- read file contents into a string
   Copyright (C) 2006 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "strfile.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

/* Open (in binary mode) and read the contents of FILENAME, and return
   a newly allocated string with the content, and set LENGTH to the
   length of the string.  On errors, return NULL and sets errno.  */
char *
strfile (const char *filename, size_t *length)
{
  FILE *fh;
  char *out = NULL;
  size_t pos = 0;

  fh = fopen (filename, "rb");
  if (!fh)
    return NULL;

  do {
    size_t nread;
    char *tmp = realloc (out, pos + BUFSIZ);

    if (!tmp)
      {
	int save_errno = errno;
	if (out)
	  free (out);
	errno = save_errno;
	return NULL;
      }
    out = tmp;

    nread = fread (out + pos, 1, BUFSIZ, fh);
    pos += nread;
  } while (!feof (fh) && !ferror (fh));

  if (!(feof (fh) && fclose (fh)))
    {
      int save_errno = errno;
      free (out);
      errno = save_errno;
      return NULL;
    }

  *length = pos;

  return out;
}
