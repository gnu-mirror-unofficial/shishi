/* done.c	deconstructor
 * Copyright (C) 2002, 2003  Simon Josefsson
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
 * tkts, it is written to the default tkts file (call
 * shishi_tkts_default_file_set() to change the default tkts
 * file). If you do not wish to write the default tkts file,
 * close the default tkts with shishi_tkts_done(handle,
 * NULL) before calling this function.
 **/
void
shishi_done (Shishi * handle)
{
  if (handle->tkts)
    {
      shishi_tkts_to_file (handle->tkts, shishi_tkts_default_file (handle));

      shishi_tkts_done (&handle->tkts);
    }

  /*  if (handle->default_realm)
     free (handle->default_realm); */
  if (handle->usercfgfile)
    free (handle->usercfgfile);
  if (handle->tktsdefaultfile)
    free (handle->tktsdefaultfile);
  if (handle->hostkeysdefaultfile)
    free (handle->hostkeysdefaultfile);
  if (handle->clientkdcetypes)
    free (handle->clientkdcetypes);

  if (handle->asn1)
    shishi_asn1_done (handle, handle->asn1);

  free (handle);
}
