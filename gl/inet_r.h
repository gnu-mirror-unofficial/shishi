/* inet_r.h -- Thread safe version of arpa/inet.h function inet_ntoa.
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

#ifndef INET_R_H
# define INET_R_H

/* Get struct in_addr. */
#include <arpa/inet.h>

/* Convert the Internet host address IN given in network byte order to
   a string in standard numbers-and-dots notation.  The string is
   stored in the provided buffer BUF, which must have room for at
   least 16 bytes ("ddd.ddd.ddd.ddd\0").  A pointer to BUF is
   returned. */
char *inet_ntoa_r (struct in_addr in, char *buf);

#endif /* INET_R_H */
