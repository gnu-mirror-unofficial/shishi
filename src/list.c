/* list.c	list credentials
 * Copyright (C) 2002  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "data.h"

int
list (Shishi * handle, Shishi_ticketset * ticketset, struct arguments arg)
{
  int res;

  if (!arg.silent)
    printf (_("Tickets in `%s':\n"), arg.ticketfile);

  res = shishi_ticketset_print_for_service (handle, ticketset, 
					    stdout, arg.sname);
  if (res != SHISHI_OK)
    {
      fprintf (stderr, "Could not list tickets: %s", shishi_strerror (res));
      return res;
    }

  return SHISHI_OK;
}
