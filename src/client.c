/* client.c	sample network client using shishi
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
client (Shishi * handle, struct arguments arg)
{
  Shishi_ticket *tkt;
  Shishi_ap *ap;
  int res;

  if (arg.cname == NULL)
    arg.cname = shishi_principal_default (handle);

  if (arg.verbose)
    printf ("Service name: `%s'\n", arg.sname);

  tkt = shishi_ticketset_get_ticket_for_server (handle, NULL, arg.sname);
  if (tkt == NULL)
    {
      printf ("Cannot get ticket for server `%s'.\n", arg.sname);
      return res;
    }

  res = shishi_ap_data (handle, tkt, NULL, 0, &ap);
  if (res != SHISHI_OK)
    {
      printf ("Could not create AP: %s", shishi_strerror (res));
      return res;
    }

  res = shishi_apreq_options_set (handle, shishi_ap_get_apreq(ap),
				  arg.apoptions);
  if (res != SHISHI_OK)
    {
      printf ("Could not set AP-Options: %s", shishi_strerror (res));
      return res;
    }

  if (arg.verbose)
    shishi_authenticator_print (handle, stdout,
				shishi_ap_get_authenticator(ap));

  shishi_apreq_print (handle, stdout, shishi_ap_get_apreq(ap));

  if (shishi_apreq_mutual_required_p (handle, shishi_ap_get_apreq(ap)))
    {
      ASN1_TYPE aprep;

      printf ("Waiting for AP-REP from server...\n");

      res = shishi_aprep_parse (handle, stdin, &aprep);

      res = shishi_ap_reply_verify (handle, ap, aprep);
      if (res == SHISHI_APREP_VERIFY_FAILED)
	printf("AP-REP verification failed...\n");
      else if (res == SHISHI_OK)
	printf("AP-REP verification OK...\n");
      else
	printf("AP-REP verification error: %s\n", shishi_strerror(res));
    }

  return SHISHI_OK;
}
