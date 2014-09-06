/* encticketpart.c --- Shishi encticketpart self tests.
 * Copyright (C) 2012-2014 Simon Josefsson
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

/* Check that principals are encoded properly in encticketpart.
   http://permalink.gmane.org/gmane.comp.gnu.shishi.general/711
*/

#include "utils.c"

void
test (Shishi * handle)
{
  Shishi_asn1 encticketpart;
  char *client;
  size_t clientlen;
  uint32_t i;
  int res;

  encticketpart = shishi_encticketpart (handle);
  if (encticketpart)
    success ("shishi_encticketpart() OK\n");
  else
    fail ("shishi_encticketpart() failed\n");

  res = shishi_encticketpart_cname_set (handle,
					encticketpart,
					42,
					"foo/bar");
  if (debug)
    {
      res = shishi_encticketpart_print (handle, stdout, encticketpart);
      if (res == SHISHI_OK)
	success ("shishi_encticketpart_print() OK\n");
      else
	fail ("shishi_encticketpart_print() failed\n");
    }

  res = shishi_encticketpart_client (handle, encticketpart,
				     &client, &clientlen);
  if (res == SHISHI_OK)
    success ("shishi_encticketpart_client() OK\n");
  else
    fail ("shishi_encticketpart_client() failed\n");

  if (clientlen == strlen ("foo/bar") &&
      memcmp ("foo/bar", client, clientlen) == 0)
    success ("encticketpart encoding OK\n");
  else
    fail ("encticketpart encoding failed\n");


  res = shishi_asn1_read_uint32 (handle, encticketpart,
				 "cname.name-type", &i);
  if (res == SHISHI_OK)
    success ("shishi_asn1_read_uint32() OK\n");
  else
    fail ("shishi_asn1_read_uint32() failed\n");
  if (i != 42)
    fail ("encticketpart name-type failed (%d)\n", i);
}
