/* xstrndup.c -- copy at most n bytes of a string with out of memory checking
   Copyright (C) 2003 Simon Josefsson

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
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#if STDC_HEADERS || HAVE_STRING_H
# include <string.h>
#else
# include <strings.h>
#endif

#include <sys/types.h>

#include "xalloc.h"

/* Return a newly allocated copy of at most n bytes of STRING.  */

char *
xstrndup (const char *string, size_t n)
{
  /* FIXME we may allocate more than needed amount. however strlen()
     may read out of bounds in case string is never zero
     terminated. looping through string (limited by n) waste cpu, this
     waste memory. */
  return strncpy (xmalloc (n), string, n);
}
