/* xinet.c -- arpa/inet.h function inet_ntoa that allocate output buffer.
   Copyright (C) 2004 Free Software Foundation, Inc.
   Written by Simon Josefsson.

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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

/* Specification. */
#include "xinet.h"

/* Get inet_ntoa_r. */
#include "inet_r.h"

/* Get xmalloc. */
#include "xalloc.h"

char *
xinet_ntoa (struct in_addr in)
{
  char *p = xmalloc (16);
  return inet_ntoa_r (in, p);
}
