/* done.c	deconstructor
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

#include "internal.h"

/**
 * shishi_done:
 * @handle: shishi handle as allocated by shishi_init().
 *
 * Deallocates the shishi library handle.  The handle must not be used
 * in any calls to shishi functions after this.  If there is a default
 * ticketset, it is written to the default ticketset file (call
 * shishi_ticketset_default_file_set() to change the default ticketset
 * file). If you do not wish to write the default ticketset file,
 * close the default ticketset with shishi_ticketset_done(handle,
 * NULL) before calling this function.
 **/
void
shishi_done (Shishi * handle)
{
  if (handle->ticketset)
    {
      shishi_ticketset_to_file (handle->ticketset,
				shishi_ticketset_default_file (handle));

      shishi_ticketset_done (&handle->ticketset);
    }

  /*  if (handle->default_realm)
     free (handle->default_realm); */
  if (handle->usercfgfile)
    free (handle->usercfgfile);
  if (handle->ticketsetdefaultfile)
    free (handle->ticketsetdefaultfile);
  if (handle->hostkeysdefaultfile)
    free (handle->hostkeysdefaultfile);

  if (handle->asn1)
    asn1_delete_structure (&handle->asn1);

  free (handle);
}
