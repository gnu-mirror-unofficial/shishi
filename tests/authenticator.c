/* authenticator.c	Shishi authenticator self tests.
 * Copyright (C) 2002, 2003  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with Shishi; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "utils.c"
#include <shishi.h>

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

int
main (int argc, char *argv[])
{
  Shishi *handle;
  Shishi_asn1 a;
  char buffer[BUFSIZ];
  char buffer2[BUFSIZ];
  int n, m, res;

  do
    if (strcmp (argv[argc - 1], "-v") == 0 ||
	strcmp (argv[argc - 1], "--verbose") == 0)
      verbose = 1;
    else if (strcmp (argv[argc - 1], "-d") == 0 ||
	     strcmp (argv[argc - 1], "--debug") == 0)
      debug = 1;
    else if (strcmp (argv[argc - 1], "-b") == 0 ||
	     strcmp (argv[argc - 1], "--break-on-error") == 0)
      break_on_error = 1;
    else if (strcmp (argv[argc - 1], "-h") == 0 ||
	     strcmp (argv[argc - 1], "-?") == 0 ||
	     strcmp (argv[argc - 1], "--help") == 0)
      {
	printf ("Usage: %s [-vdbh?] [--verbose] [--debug] "
		"[--break-on-error] [--help]\n", argv[0]);
	return 1;
      }
  while (argc-- > 1);

  handle = shishi ();
  if (handle == NULL)
    {
      fail ("Could not initialize shishi\n");
      return 1;
    }

  if (debug)
    shishi_cfg (handle, strdup ("verbose"));

  escapeprint (NULL, 0);
  hexprint (NULL, 0);
  binprint (NULL, 0);

  /* shishi_authenticator() */
  a = shishi_authenticator (handle);
  if (debug)
    printf ("shishi_authenticator () => `%p'.\n", a);
  if (a)
    success ("shishi_authenticator() OK\n");
  else
    fail ("shishi_authenticator() failed\n");

  res = shishi_authenticator_remove_subkey (handle, a);
  if (res == SHISHI_OK)
    success ("shishi_authenticator() OK\n");
  else
    fail ("shishi_authenticator() failed\n");

  /* shishi_authenticator_set_crealm() */
  res = shishi_authenticator_set_crealm (handle, a, "foo");
  if (res == SHISHI_OK)
    success ("shishi_authenticator_set_crealm() OK\n");
  else
    fail ("shishi_authenticator_set_crealm() failed\n");

  /* shishi_authenticator_client_set() */
  res = shishi_authenticator_client_set (handle, a, "foo/bar/baz");
  if (res == SHISHI_OK)
    success ("shishi_authenticator_client_set() OK\n");
  else
    fail ("shishi_authenticator_client_set() failed\n");

  /* shishi_authenticator_cname_get() */
  n = sizeof (buffer);
  res = shishi_authenticator_cname_get (handle, a, buffer, &n);
  if (debug)
    escapeprint (buffer, n);
  if (res == SHISHI_OK &&
      n == strlen ("foo/bar/baz") && memcmp (buffer, "foo/bar/baz", n) == 0)
    success ("shishi_authenticator_cname_get() OK\n");
  else
    fail ("shishi_authenticator_cname_get() failed\n");

  /* shishi_authenticator_client_set() */
  res = shishi_authenticator_client_set (handle, a, "foo");
  if (res == SHISHI_OK)
    success ("shishi_authenticator_client_set() OK\n");
  else
    fail ("shishi_authenticator_client_set() failed\n");

  /* shishi_authenticator_cname_get() */
  n = sizeof (buffer);
  res = shishi_authenticator_cname_get (handle, a, buffer, &n);
  if (debug)
    escapeprint (buffer, n);
  if (res == SHISHI_OK && n == strlen ("foo")
      && memcmp (buffer, "foo", n) == 0)
    success ("shishi_authenticator_cname_get() OK\n");
  else
    fail ("shishi_authenticator_cname_get() failed\n");

  /* shishi_authenticator_set_crealm() */
  res = shishi_authenticator_set_crealm (handle, a, "bar");
  if (res == SHISHI_OK)
    success ("shishi_authenticator_set_crealm() OK\n");
  else
    fail ("shishi_authenticator_set_crealm() failed\n");

  /* shishi_authenticator_cnamerealm_get() */
  n = sizeof (buffer);
  res = shishi_authenticator_cnamerealm_get (handle, a, buffer, &n);
  if (debug)
    escapeprint (buffer, n);
  if (res == SHISHI_OK &&
      n == strlen ("foo@bar") && memcmp (buffer, "foo@bar", n) == 0)
    success ("shishi_authenticator_cnamerealm_get() OK\n");
  else
    fail ("shishi_authenticator_cnamerealm_get() failed\n");

  /* shishi_authenticator_add_authorizationdata() */
  res = shishi_authenticator_add_authorizationdata (handle, a, 42, "baz", 3);
  if (res == SHISHI_OK)
    success ("shishi_authenticator_add_authorizationdata() OK\n");
  else
    fail ("shishi_authenticator_add_authorizationdata() failed\n");

  /* shishi_authenticator_authorizationdata() */
  m = sizeof (buffer);
  res = shishi_authenticator_authorizationdata (handle, a, &n, buffer, &m, 1);
  if (debug)
    escapeprint (buffer, m);
  if (res == SHISHI_OK && n == 42 && m == 3 && memcmp (buffer, "baz", 3) == 0)
    success ("shishi_authenticator_authorizationdata() OK\n");
  else
    fail ("shishi_authenticator_authorizationdata() failed\n");

  /* shishi_authenticator_authorizationdata() */
  m = sizeof (buffer);
  res = shishi_authenticator_authorizationdata (handle, a, &n, buffer, &m, 2);
  if (res == SHISHI_OUT_OF_RANGE)
    success ("shishi_authenticator_authorizationdata() OK\n");
  else
    fail ("shishi_authenticator_authorizationdata() failed\n");

  /* shishi_authenticator_remove_cksum() */
  res = shishi_authenticator_remove_cksum (handle, a);
  if (res == SHISHI_OK)
    success ("shishi_authenticator_remove_cksum() OK\n");
  else
    fail ("shishi_authenticator_remove_cksum() failed\n");

  /* shishi_a2d() */
  n = sizeof (buffer);
  res = shishi_a2d (handle, a, buffer, &n);
  if (res == SHISHI_OK)
    success ("shishi_a2d() OK\n");
  else
    n = 0, fail ("shishi_a2d() failed\n");

  /* shishi_authenticator_to_file() */
  res = shishi_authenticator_to_file (handle, a, SHISHI_FILETYPE_TEXT,
				      "authenticator.tmp");
  if (res == SHISHI_OK)
    success ("shishi_authenticator_to_file() OK\n");
  else
    fail ("shishi_authenticator_to_file() failed\n");

  /* shishi_asn1_done() */
  res = shishi_asn1_done (handle, a);
  if (res == SHISHI_OK)
    success ("shishi_asn1_done() OK\n");
  else
    fail ("shishi_asn1_done() failed\n");

  a = NULL;

  /* shishi_authenticator_from_file() */
  res = shishi_authenticator_from_file (handle, &a, SHISHI_FILETYPE_TEXT,
					"authenticator.tmp");
  if (res == SHISHI_OK)
    success ("shishi_authenticator_from_file() OK\n");
  else
    fail ("shishi_authenticator_from_file() failed\n");

  if (debug)
    {
      /* shishi_authenticator_print() */
      res = shishi_authenticator_print (handle, stdout, a);
      if (res == SHISHI_OK)
	success ("shishi_authenticator_print() OK\n");
      else
	fail ("shishi_authenticator_print() failed\n");
    }

  /* shishi_a2d() */
  m = sizeof (buffer2);
  res = shishi_a2d (handle, a, buffer2, &m);
  if (res == SHISHI_OK)
    success ("shishi_a2d() OK\n");
  else
    n = 0, fail ("shishi_a2d() failed\n");

  /* Compare DER encodings of authenticators */
  if (n > 0 && m > 0 && n == m && memcmp (buffer, buffer2, n) == 0)
    success ("DER comparison OK\n");
  else
    fail ("DER comparison failed\n");

  /* shishi_authenticator_cusec_set() */
  res = shishi_authenticator_cusec_set (handle, a, 4711);
  if (res == SHISHI_OK)
    success ("shishi_authenticator_cusec_set() OK\n");
  else
    fail ("shishi_authenticator_cusec_set() failed\n");

  /* shishi_authenticator_cusec_get() */
  res = shishi_authenticator_cusec_get (handle, a, &n);
  if (debug)
    printf ("shishi_authenticator_cusec_get () => `%d'.\n", n);
  if (res == SHISHI_OK && n == 4711)
    success ("shishi_authenticator_cusec_get() OK\n");
  else
    fail ("shishi_authenticator_cusec_get() failed\n");

  /* shishi_authenticator_ctime_set() */
  res = shishi_authenticator_ctime_set (handle, a, "19700101011831Z");
  if (res == SHISHI_OK)
    success ("shishi_authenticator_ctime_set() OK\n");
  else
    fail ("shishi_authenticator_ctime_set() failed\n");

  /* shishi_authenticator_ctime_get() */
  res = shishi_authenticator_ctime_get (handle, a, buffer);
  if (debug)
    escapeprint (buffer, 15);
  if (res == SHISHI_OK && memcmp (buffer, "19700101011831Z", 15) == 0)
    success ("shishi_authenticator_ctime_get() OK\n");
  else
    fail ("shishi_authenticator_ctime_get() failed\n");

  /* shishi_a2d() */
  n = sizeof (buffer);
  res = shishi_a2d (handle, a, buffer, &n);
  if (res == SHISHI_OK)
    success ("shishi_a2d() OK\n");
  else
    n = 0, fail ("shishi_a2d() failed\n");
  if (debug)
    {
      shishi_authenticator_print (handle, stdout, a);
      hexprint (buffer, n);
      puts ("");
      hexprint (authenticator, sizeof (authenticator));
      puts ("");
    }
  if (n == sizeof (authenticator) &&
      n == AUTHENTICATOR_LEN && memcmp (authenticator, buffer, n) == 0)
    success ("DER comparison OK\n");
  else
    fail ("DER comparison failed\n");

  /* shishi_authenticator_clear_authorizationdata() */
  res = shishi_authenticator_clear_authorizationdata (handle, a);
  if (res == SHISHI_OK)
    success ("shishi_authenticator_clear_authorizationdata() OK\n");
  else
    fail ("shishi_authenticator_clear_authorizationdata() failed\n");

  /* shishi_a2d() */
  n = sizeof (buffer);
  res = shishi_a2d (handle, a, buffer, &n);
  if (res == SHISHI_OK)
    success ("shishi_a2d() OK\n");
  else
    n = 0, fail ("shishi_a2d() failed\n");
  if (debug)
    {
      shishi_authenticator_print (handle, stdout, a);
      hexprint (buffer, n);
      puts ("");
      hexprint (authenticator2, sizeof (authenticator2));
      puts ("");
    }
  if (n == sizeof (authenticator2) &&
      n == AUTHENTICATOR2_LEN && memcmp (authenticator2, buffer, n) == 0)
    success ("DER comparison OK\n");
  else
    fail ("DER comparison failed\n");

  /* unlink() */
  res = unlink ("authenticator.tmp");
  if (res == 0)
    success ("unlink() OK\n");
  else
    fail ("unlink() failed\n");

  shishi_done (handle);

  if (verbose)
    printf ("Authenticator self tests done with %d errors\n", error_count);

  return error_count ? 1 : 0;
}
