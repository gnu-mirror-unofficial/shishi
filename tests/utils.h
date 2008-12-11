/* utils.h --- Prototypes for self test utilities.
 * Copyright (C) 2002, 2003, 2004, 2005, 2007, 2008  Simon Josefsson
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

#ifndef UTILS_H
# define UTILS_H

# include <stdio.h>
# include <stdlib.h>
# include <stdarg.h>
# include <ctype.h>
# include <stdint.h>
# include <sys/types.h>
# include <sys/select.h>
# include <sys/socket.h>
# include <unistd.h>
# include <string.h>
# include <sys/time.h>
# include <time.h>
# include <netdb.h>
# include <errno.h>

# include <shishi.h>

#include "base64.h"

extern int debug;
extern int error_count;
extern int break_on_error;

extern void fail (const char *format, ...)
  __attribute__ ((format (printf, 1, 2)));
extern void success (const char *format, ...)
  __attribute__ ((format (printf, 1, 2)));
extern void escapeprint (const char *str, size_t len);
extern void hexprint (const char *str, size_t len);
extern void binprint (const char *str, size_t len);

/* This must be implemented elsewhere. */
extern void test (Shishi *handle);

#endif /* UTILS_H */
