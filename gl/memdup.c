/* Duplicate N bytes of data buffer.
   Copyright (C) 2003 Free Software Foundation, Inc.

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

/* Specification.  */
#include "memdup.h"

/* Get malloc */
#include <stdlib.h>

/* Get memcpy */
#include <string.h>

/* Duplicate N bytes of data buffer. */
extern void *
memdup (const void *src, size_t n)
{
  void *dest;
  dest = malloc (n);
  if (!dest)
    return NULL;
  memcpy (dest, src, n);
  return dest;
}
