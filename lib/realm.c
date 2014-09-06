/* realm.c --- Realm related functions.
 * Copyright (C) 2002-2014 Simon Josefsson
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
 * Guesses a realm based on getdomainname(), which really responds
 * with a NIS/YP domain, but if set properly, it might be a good
 * first guess.  If this NIS query fails, call gethostname(),
 * and on its failure, fall back to returning the artificial
 * string "could-not-guess-default-realm".
 *
 * Note that the hostname is not trimmed off of the string returned
 * by gethostname(), thus pretending the local host name is a valid
 * realm name.  The resulting corner case could merit a check that
 * the suggested realm is distinct from the fully qualifies host,
 * and if not, simply strip the host name from the returned string
 * before it is used in an application.  One reason for sticking
 * with the present behaviour, is that some systems respond with
 * a non-qualified host name as reply from gethostname().
 *
 * Return value: Returns a guessed realm for the running host,
 *   containing a string that has to be deallocated with
 *   free() by the caller.
 **/
char *
shishi_realm_default_guess (void)
{
  char *realm;

  realm = xgetdomainname ();
  if (realm && strlen (realm) > 0 && strcmp (realm, "(none)") != 0)
    return realm;

  free (realm);

  realm = xgethostname ();
  if (realm && strlen (realm) > 0 && strcmp (realm, "(none)") != 0)
    return realm;

  free (realm);

  realm = strdup ("could-not-guess-default-realm");

  return realm;
}

/**
 * shishi_realm_default:
 * @handle: Shishi library handle created by shishi_init().
 *
 * Determines name of default realm, i.e., the name of whatever
 * realm the library will use whenever an explicit realm is not
 * stated during a library call.
 *
 * Return value: Returns the default realm in use by the library.
 *   Not a copy, so do not modify or deallocate the returned string.
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
 * @handle: Shishi library handle created by shishi_init().
 * @realm: String stating a new default realm name, or %NULL.
 *
 * Sets the default realm used by the library; or, with @realm
 * set to %NULL, resets the library realm setting to that name
 * selected by configuration for default value.
 *
 * The string is copied into the library, so you can dispose of
 * the content in @realm immediately after calling this function.
 **/
void
shishi_realm_default_set (Shishi * handle, const char *realm)
{
  free (handle->default_realm);
  if (realm)
    handle->default_realm = xstrdup (realm);
  else
    handle->default_realm = NULL;
}

/**
 * shishi_realm_for_server_file:
 * @handle: Shishi library handle created by shishi_init().
 * @server: Hostname to determine realm for.
 *
 * Finds the realm applicable to a host @server, using the
 * standard configuration file.
 *
 * Return value: Returns realm for host, or %NULL if not known.
 **/
char *
shishi_realm_for_server_file (Shishi * handle, char *server)
{
  struct Shishi_realminfo *ri;
  size_t i, j;
  char *p;

  for (i = 0; i < handle->nrealminfos; i++)
    {
      ri = &handle->realminfos[i];

      if (!ri->nserverwildcards)
	continue;

      for (j = 0; j < ri->nserverwildcards; j++)
	{
	  /* Exact server name match.  */
	  if (strcmp (server, ri->serverwildcards[j]) == 0)
	    return ri->name;

	  /* Is this a tail pattern?  */
	  if (*(ri->serverwildcards[j]) != '.')
	    continue;

	  /* Domain part matching.  */
	  p = server;
	  while ((p = strchr (p, '.')))
	    if (strcmp (p++, ri->serverwildcards[j]) == 0)
	      return ri->name;
	}
    }

  return NULL;
}

/**
 * shishi_realm_for_server_dns:
 * @handle: Shishi library handle created by shishi_init().
 * @server: Hostname to find realm for.
 *
 * Finds the realm for a host @server using DNS lookup, as is
 * prescribed in "draft-ietf-krb-wg-krb-dns-locate-03.txt".
 *
 * Since DNS lookup can be spoofed, relying on the realm information
 * may result in a redirection attack.  In a single-realm scenario,
 * this only achieves a denial of service, but with trust across
 * multiple realms the attack may redirect you to a compromised realm.
 * For this reason, Shishi prints a warning, suggesting that the user
 * should instead add a proper 'server-realm' configuration token.
 *
 * To illustrate the DNS information used, here is an extract from a
 * zone file for the domain ASDF.COM:
 *
 * _kerberos.asdf.com.             IN   TXT     "ASDF.COM"
 * _kerberos.mrkserver.asdf.com.   IN   TXT     "MARKETING.ASDF.COM"
 * _kerberos.salesserver.asdf.com. IN   TXT     "SALES.ASDF.COM"
 *
 * Let us suppose that in this case, a client wishes to use a service
 * on the host "foo.asdf.com".  It would first query for
 *
 * _kerberos.foo.asdf.com.  IN TXT
 *
 * Finding no match, it would then query for
 *
 * _kerberos.asdf.com.      IN TXT
 *
 * With the resource records stated above, the latter query returns
 * a positive answer.
 *
 * Return value: Returns realm for the indicated host, or %NULL
 *   if no relevant TXT record could be found.
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
 * @handle: Shishi library handle created by shishi_init().
 * @server: Hostname to find realm for.
 *
 * Finds a realm for the host @server, using various methods.
 *
 * Currently this includes static configuration files, using
 * the library call shishi_realm_for_server_file(), and DNS
 * lookup using shishi_realm_for_server_dns().  They are
 * attempted in the stated order.  See the documentation of
 * either function for more information.
 *
 * Return value: Returns realm for the indicated host, or %NULL
 *   if nothing is known about @server.
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
