/* xinet.h -- arpa/inet.h function inet_ntoa that allocate output buffer.
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

#ifndef XINET_H
# define XINET_H

/* Get struct in_addr. */
#include <arpa/inet.h>

/* Convert the Internet host address IN given in network byte order to
   a string in standard numbers-and-dots notation.  The string is
   newly allocated, with error checking, and must be deallocate by the
   caller. */
char *xinet_ntoa (struct in_addr in);

#endif /* XINET_H */
