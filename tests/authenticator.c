/* authenticator.c --- Shishi authenticator self tests.
 * Copyright (C) 2002, 2003, 2004, 2006, 2007  Simon Josefsson
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

#include "utils.c"

static const char authenticator[] = {
  '\x62', '\x4b', '\x30', '\x49', '\xa0', '\x03', '\x02', '\x01',
  '\x05', '\xa1', '\x05', '\x1b', '\x03', '\x62', '\x61', '\x72',
  '\xa2', '\x10', '\x30', '\x0e', '\xa0', '\x03', '\x02', '\x01',
  '\x00', '\xa1', '\x07', '\x30', '\x05', '\x1b', '\x03', '\x66',
  '\x6f', '\x6f', '\xa4', '\x04', '\x02', '\x02', '\x12', '\x67',
  '\xa5', '\x11', '\x18', '\x0f', '\x31', '\x39', '\x37', '\x30',
  '\x30', '\x31', '\x30', '\x31', '\x30', '\x31', '\x31', '\x38',
  '\x33', '\x31', '\x5a', '\xa8', '\x10', '\x30', '\x0e', '\x30',
  '\x0c', '\xa0', '\x03', '\x02', '\x01', '\x2a', '\xa1', '\x05',
  '\x04', '\x03', '\x62', '\x61', '\x7a'
};

static const char authenticator2[] = {
  '\x62', '\x39', '\x30', '\x37', '\xa0', '\x03', '\x02', '\x01',
  '\x05', '\xa1', '\x05', '\x1b', '\x03', '\x62', '\x61', '\x72',
  '\xa2', '\x10', '\x30', '\x0e', '\xa0', '\x03', '\x02', '\x01',
  '\x00', '\xa1', '\x07', '\x30', '\x05', '\x1b', '\x03', '\x66',
  '\x6f', '\x6f', '\xa4', '\x04', '\x02', '\x02', '\x12', '\x67',
  '\xa5', '\x11', '\x18', '\x0f', '\x31', '\x39', '\x37', '\x30',
  '\x30', '\x31', '\x30', '\x31', '\x30', '\x31', '\x31', '\x38',
  '\x33', '\x31', '\x5a'
};

#define AUTHENTICATOR_LEN 77
#define AUTHENTICATOR2_LEN 59

void
test (Shishi * handle)
{
  Shishi_asn1 a;
  char *p, *buf, *buf2;
  int res;
  size_t n, m;
  int32_t t;
  uint32_t s;

  /* shishi_authenticator */
  a = shishi_authenticator (handle);
  if (debug)
    printf ("shishi_authenticator () => `%p'.\n", a);
  if (a)
    success ("shishi_authenticator() OK\n");
  else
    fail ("shishi_authenticator() failed\n");

  if (debug)
    shishi_authenticator_print (handle, stdout, a);

  res = shishi_authenticator_remove_subkey (handle, a);
  if (res == SHISHI_OK)
    success ("shishi_authenticator_remove_subkey() OK\n");
  else
    fail ("shishi_authenticator_remove_subkey() failed\n");

  /* shishi_authenticator_seqnumber_get */
  res = shishi_authenticator_seqnumber_get (handle, a, &s);
  if (res == SHISHI_OK)
    success ("shishi_authenticator_seqnumber_get() OK\n");
  else
    fail ("shishi_authenticator_seqnumber_get() failed\n");

  /* shishi_authenticator_seqnumber_set */
  res = shishi_authenticator_seqnumber_set (handle, a, 42);
  if (res == SHISHI_OK)
    success ("shishi_authenticator_seqnumber_set() OK\n");
  else
    fail ("shishi_authenticator_seqnumber_set() failed\n");

  /* shishi_authenticator_seqnumber_get */
  res = shishi_authenticator_seqnumber_get (handle, a, &s);
  if (res == SHISHI_OK && s == 42)
    success ("shishi_authenticator_seqnumber_get() OK\n");
  else
    fail ("shishi_authenticator_seqnumber_get() failed\n");

  /* shishi_authenticator_seqnumber_remove */
  res = shishi_authenticator_seqnumber_remove (handle, a);
  if (res == SHISHI_OK)
    success ("shishi_authenticator_seqnumber_remove() OK\n");
  else
    fail ("shishi_authenticator_seqnumber_remove() failed\n");

  /* shishi_authenticator_set_crealm */
  res = shishi_authenticator_set_crealm (handle, a, "foo");
  if (res == SHISHI_OK)
    success ("shishi_authenticator_set_crealm() OK\n");
  else
    fail ("shishi_authenticator_set_crealm() failed\n");

  /* shishi_authenticator_client_set */
  res = shishi_authenticator_client_set (handle, a, "foo/bar/baz");
  if (res == SHISHI_OK)
    success ("shishi_authenticator_client_set() OK\n");
  else
    fail ("shishi_authenticator_client_set() failed\n");

  /* shishi_authenticator_client */
  res = shishi_authenticator_client (handle, a, &buf, &n);
  if (debug)
    escapeprint (buf, n);
  if (res == SHISHI_OK &&
      n == strlen ("foo/bar/baz") && memcmp (buf, "foo/bar/baz", n) == 0)
    success ("shishi_authenticator_client() OK\n");
  else
    fail ("shishi_authenticator_client() failed\n");
  if (res == SHISHI_OK)
    free (buf);

  /* shishi_authenticator_client_set */
  res = shishi_authenticator_client_set (handle, a, "foo");
  if (res == SHISHI_OK)
    success ("shishi_authenticator_client_set() OK\n");
  else
    fail ("shishi_authenticator_client_set() failed\n");

  /* shishi_authenticator_client */
  res = shishi_authenticator_client (handle, a, &buf, &n);
  if (debug)
    escapeprint (buf, n);
  if (res == SHISHI_OK && n == strlen ("foo") && memcmp (buf, "foo", n) == 0)
    success ("shishi_authenticator_client() OK\n");
  else
    fail ("shishi_authenticator_client() failed\n");
  if (res == SHISHI_OK)
    free (buf);

  /* shishi_authenticator_set_crealm */
  res = shishi_authenticator_set_crealm (handle, a, "bar");
  if (res == SHISHI_OK)
    success ("shishi_authenticator_set_crealm() OK\n");
  else
    fail ("shishi_authenticator_set_crealm() failed\n");

  /* shishi_authenticator_clientrealm */
  res = shishi_authenticator_clientrealm (handle, a, &buf, &n);
  if (debug)
    escapeprint (buf, n);
  if (res == SHISHI_OK &&
      n == strlen ("foo@bar") && memcmp (buf, "foo@bar", n) == 0)
    success ("shishi_authenticator_clientrealm() OK\n");
  else
    fail ("shishi_authenticator_clientrealm() failed\n");
  if (res == SHISHI_OK)
    free (buf);

  /* shishi_authenticator_add_authorizationdata */
  res = shishi_authenticator_add_authorizationdata (handle, a, 42, "baz", 3);
  if (res == SHISHI_OK)
    success ("shishi_authenticator_add_authorizationdata() OK\n");
  else
    fail ("shishi_authenticator_add_authorizationdata() failed\n");

  /* shishi_authenticator_authorizationdata */
  res = shishi_authenticator_authorizationdata (handle, a, &t, &buf, &m, 1);
  if (debug)
    escapeprint (buf, m);
  if (res == SHISHI_OK && t == 42 && m == 3 && memcmp (buf, "baz", 3) == 0)
    success ("shishi_authenticator_authorizationdata() OK\n");
  else
    fail ("shishi_authenticator_authorizationdata() failed\n");
  if (res == SHISHI_OK)
    free (buf);

  /* shishi_authenticator_authorizationdata */
  res = shishi_authenticator_authorizationdata (handle, a, &t, &buf, &m, 2);
  if (res == SHISHI_OK)
    free (buf);
  if (res == SHISHI_OUT_OF_RANGE)
    success ("shishi_authenticator_authorizationdata() OK\n");
  else
    fail ("shishi_authenticator_authorizationdata() failed\n");

  /* shishi_authenticator_remove_cksum */
  res = shishi_authenticator_remove_cksum (handle, a);
  if (res == SHISHI_OK)
    success ("shishi_authenticator_remove_cksum() OK\n");
  else
    fail ("shishi_authenticator_remove_cksum() failed\n");

  /* shishi_asn1_to_der */
  res = shishi_asn1_to_der (handle, a, &buf, &n);
  if (res == SHISHI_OK)
    success ("shishi_asn1_to_der() OK\n");
  else
    n = 0, fail ("shishi_asn1_to_der() failed\n");

  /* shishi_authenticator_to_file */
  res = shishi_authenticator_to_file (handle, a, SHISHI_FILETYPE_TEXT,
				      "authenticator.tmp");
  if (res == SHISHI_OK)
    success ("shishi_authenticator_to_file() OK\n");
  else
    fail ("shishi_authenticator_to_file() failed\n");

  /* shishi_asn1_done */
  shishi_asn1_done (handle, a);
  success ("shishi_asn1_done() OK\n");

  a = NULL;

  /* shishi_authenticator_from_file */
  res = shishi_authenticator_from_file (handle, &a, SHISHI_FILETYPE_TEXT,
					"authenticator.tmp");
  if (res == SHISHI_OK)
    success ("shishi_authenticator_from_file() OK\n");
  else
    fail ("shishi_authenticator_from_file() failed\n");

  if (debug)
    {
      /* shishi_authenticator_print */
      res = shishi_authenticator_print (handle, stdout, a);
      if (res == SHISHI_OK)
	success ("shishi_authenticator_print() OK\n");
      else
	fail ("shishi_authenticator_print() failed\n");
    }

  /* shishi_asn1_to_der */
  res = shishi_asn1_to_der (handle, a, &buf2, &m);
  if (res == SHISHI_OK)
    success ("shishi_asn1_to_der() OK\n");
  else
    n = 0, fail ("shishi_asn1_to_der() failed\n");

  /* Compare DER encodings of authenticators */
  if (n > 0 && m > 0 && n == m && memcmp (buf, buf2, n) == 0)
    success ("DER comparison OK\n");
  else
    fail ("DER comparison failed\n");

  free (buf);
  free (buf2);

  /* shishi_authenticator_cusec_set */
  res = shishi_authenticator_cusec_set (handle, a, 4711);
  if (res == SHISHI_OK)
    success ("shishi_authenticator_cusec_set() OK\n");
  else
    fail ("shishi_authenticator_cusec_set() failed\n");

  /* shishi_authenticator_cusec_get */
  res = shishi_authenticator_cusec_get (handle, a, &s);
  if (debug)
    printf ("shishi_authenticator_cusec_get () => `%d'.\n", t);
  if (res == SHISHI_OK && s == 4711)
    success ("shishi_authenticator_cusec_get() OK\n");
  else
    fail ("shishi_authenticator_cusec_get() failed\n");

  /* shishi_authenticator_ctime_set */
  res = shishi_authenticator_ctime_set (handle, a, "19700101011831Z");
  if (res == SHISHI_OK)
    success ("shishi_authenticator_ctime_set() OK\n");
  else
    fail ("shishi_authenticator_ctime_set() failed\n");

  /* shishi_authenticator_ctime */
  res = shishi_authenticator_ctime (handle, a, &p);
  if (debug)
    escapeprint (p, strlen (p));
  if (res == SHISHI_OK && memcmp (p, "19700101011831Z", 15) == 0)
    success ("shishi_authenticator_ctime() OK\n");
  else
    fail ("shishi_authenticator_ctime() failed\n");
  if (res == SHISHI_OK)
    free (p);

  /* shishi_asn1_to_der */
  res = shishi_asn1_to_der (handle, a, &buf, &n);
  if (res == SHISHI_OK)
    success ("shishi_asn1_to_der() OK\n");
  else
    n = 0, fail ("shishi_asn1_to_der() failed\n");
  if (debug)
    {
      shishi_authenticator_print (handle, stdout, a);
      hexprint (buf, n);
      puts ("");
      hexprint (authenticator, sizeof (authenticator));
      puts ("");
    }
  if (n == sizeof (authenticator) &&
      n == AUTHENTICATOR_LEN && memcmp (authenticator, buf, n) == 0)
    success ("DER comparison OK\n");
  else
    fail ("DER comparison failed\n");

  free (buf);

  /* shishi_authenticator_clear_authorizationdata */
  res = shishi_authenticator_clear_authorizationdata (handle, a);
  if (res == SHISHI_OK)
    success ("shishi_authenticator_clear_authorizationdata() OK\n");
  else
    fail ("shishi_authenticator_clear_authorizationdata() failed\n");

  /* shishi_asn1_to_der */
  res = shishi_asn1_to_der (handle, a, &buf, &n);
  if (res == SHISHI_OK)
    success ("shishi_asn1_to_der() OK\n");
  else
    n = 0, fail ("shishi_asn1_to_der() failed\n");
  if (debug)
    {
      shishi_authenticator_print (handle, stdout, a);
      hexprint (buf, n);
      puts ("");
      hexprint (authenticator2, sizeof (authenticator2));
      puts ("");
    }
  if (n == sizeof (authenticator2) &&
      n == AUTHENTICATOR2_LEN && memcmp (authenticator2, buf, n) == 0)
    success ("DER comparison OK\n");
  else
    fail ("DER comparison failed\n");

  free (buf);

  /* unlink */
  res = unlink ("authenticator.tmp");
  if (res == 0)
    success ("unlink() OK\n");
  else
    fail ("unlink() failed\n");
}
