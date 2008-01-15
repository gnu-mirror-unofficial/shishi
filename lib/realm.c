/* realm.c --- Realm related functions.
 * Copyright (C) 2002, 2003, 2004, 2007, 2008  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#include "internal.h"

/**
 * shishi_realm_default_guess:
 *
 * Guesses a realm based on getdomainname() (which really is NIS/YP
 * domain, but if it is set it might be a good guess), or if it fails,
 * based on gethostname(), or if it fails, the string
 * "could-not-guess-default-realm". Note that the hostname is not
 * trimmed off of the data returned by gethostname() to get the domain
 * name and use that as the realm.
 *
 * Return value: Returns guessed realm for host as a string that has
 * to be deallocated with free() by the caller.
 **/
char *
shishi_realm_default_guess (void)
{
  char *realm;

  realm = xgetdomainname ();
  if (realm && strlen (realm) > 0 && strcmp (realm, "(none)") != 0)
    return realm;

  if (realm)
    free (realm);

  realm = xgethostname ();
  if (realm && strlen (realm) > 0 && strcmp (realm, "(none)") != 0)
    return realm;

  if (realm)
    free (realm);

  realm = strdup ("could-not-guess-default-realm");

  return realm;
}

/**
 * shishi_realm_default:
 * @handle: Shishi library handle create by shishi_init().
 *
 * Get name of default realm.
 *
 * Return value: Returns the default realm used in the library.  (Not
 * a copy of it, so don't modify or deallocate it.)
 **/
const char *
shishi_realm_default (Shishi * handle)
{
  if (!handle->default_realm)
    {
      char *p;
      p = shishi_realm_default_guess ();
      shishi_realm_default_set (handle, p);
      free (p);
    }

  return handle->default_realm;
}

/**
 * shishi_realm_default_set:
 * @handle: Shishi library handle create by shishi_init().
 * @realm: string with new default realm name, or NULL to reset to default.
 *
 * Set the default realm used in the library.  The string is copied
 * into the library, so you can dispose of the variable immediately
 * after calling this function.
 **/
void
shishi_realm_default_set (Shishi * handle, const char *realm)
{
  if (handle->default_realm)
    free (handle->default_realm);
  if (realm)
    handle->default_realm = xstrdup (realm);
  else
    handle->default_realm = NULL;
}

/**
 * shishi_realm_for_server_file:
 * @handle: Shishi library handle create by shishi_init().
 * @server: hostname to find realm for.
 *
 * Find realm for a host using configuration file.
 *
 * Return value: Returns realm for host, or NULL if not found.
 **/
char *
shishi_realm_for_server_file (Shishi * handle, char *server)
{
  return NULL;
}

/**
 * shishi_realm_for_server_dns:
 * @handle: Shishi library handle create by shishi_init().
 * @server: hostname to find realm for.
 *
 * Find realm for a host using DNS lookups, according to
 * draft-ietf-krb-wg-krb-dns-locate-03.txt.  Since DNS lookups may be
 * spoofed, relying on the realm information may result in a
 * redirection attack.  In a single-realm scenario, this only achieves
 * a denial of service, but with cross-realm trust it may redirect you
 * to a compromised realm.  For this reason, Shishi prints a warning,
 * suggesting that the user should add the proper 'server-realm'
 * configuration tokens instead.
 *
 * To illustrate the DNS information used, here is an extract from a
 * zone file for the domain ASDF.COM:
 *
 * _kerberos.asdf.com.             IN      TXT     "ASDF.COM"
 * _kerberos.mrkserver.asdf.com.   IN      TXT     "MARKETING.ASDF.COM"
 * _kerberos.salesserver.asdf.com. IN      TXT     "SALES.ASDF.COM"
 *
 * Let us suppose that in this case, a client wishes to use a service
 * on the host foo.asdf.com.  It would first query:
 *
 * _kerberos.foo.asdf.com. IN TXT
 *
 * Finding no match, it would then query:
 *
 * _kerberos.asdf.com. IN TXT
 *
 * Return value: Returns realm for host, or NULL if not found.
 **/
char *
shishi_realm_for_server_dns (Shishi * handle, char *server)
{
  Shishi_dns rrs;
  char *tmp = NULL;
  char *p = server;

  do
    {
      asprintf (&tmp, "_kerberos.%s", p);
      rrs = shishi_resolv (tmp, SHISHI_DNS_TXT);
      free (tmp);
      p = strchr (p, '.');
      if (p)
	p++;
    }
  while (!rrs && p && *p);

  if (!rrs)
    return NULL;

  if (rrs->class != SHISHI_DNS_IN || rrs->type != SHISHI_DNS_TXT)
    {
      shishi_warn (handle, "Got non-TXT response to TXT query from DNS?");
      return NULL;
    }

  shishi_warn (handle, "DNS maps '%s' to '%s'.", server, (char *) rrs->rr);
  shishi_warn (handle,
	       "Consider using a 'server-realm' configuration token.");

  return rrs->rr;
}

/**
 * shishi_realm_for_server:
 * @handle: Shishi library handle create by shishi_init().
 * @server: hostname to find realm for.
 *
 * Find realm for a host, using various methods.  Currently this
 * includes static configuration files (see
 * shishi_realm_for_server_file()) and DNS (see
 * shishi_realm_for_server_dns()).
 *
 * Return value: Returns realm for host, or NULL if not found.
 **/
char *
shishi_realm_for_server (Shishi * handle, char *server)
{
  char *p;

  p = shishi_realm_for_server_file (handle, server);
  if (!p)
    p = shishi_realm_for_server_dns (handle, server);

  return p;
}
