/* xgethostname.h -- return current hostname with unlimited length
   Copyright (C) 1992, 1996, 2000, 2001, 2003 Free Software Foundation, Inc.

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

#ifndef _XGETHOSTNAME_H
#define _XGETHOSTNAME_H

/* Return the current hostname in malloc'd storage.
   If malloc fails, exit.
   Upon any other failure, return NULL.  */
extern char *xgethostname (void);

#endif /* _XGETHOSTNAME_H */
