/* authorize.c	Authorization to services of authenticated Kerberos principals.
 * Copyright (C) 2003  Simon Josefsson
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
 * shishi_authorized_p:
 * @handle: shishi handle as allocated by shishi_init().
 * @tkt: input variable with ticket info.
 * @authzname: authorization name.
 *
 * Simplistic authorization of @authzname against encrypted client
 * principal name inside ticket.  Currently this function only compare
 * the principal name with @authzname using strcmp().
 *
 * Return value: Returns 1 if authzname is authorized for services by
 *   authenticated Kerberos client principal, or 0 otherwise.
 **/
int
shishi_authorized_p (Shishi * handle, Shishi_tkt * tkt, const char *authzname)
{
  char cname[BUFSIZ];		/* XXX */
  size_t cnamelen = sizeof (cname);
  int rc;

  rc = shishi_encticketpart_cname_get (handle,
				       shishi_tkt_encticketpart (tkt),
				       cname, &cnamelen);
  if (rc != SHISHI_OK)
    return 0;

  if (strcmp (cname, authzname) == 0)
    return 1;

  return 0;
}
