/* principal.c --- Get and set default principal.
 * Copyright (C) 2002, 2003, 2004, 2006, 2007, 2008  Simon Josefsson
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
 * shishi_principal_default_guess:
 *
 * Guesses the principal name for the user, looking at environment
 * variables SHISHI_USER and USER, or if that fails, returns the
 * string "user".
 *
 * Return value: Returns guessed default principal for user as a
 * string that has to be deallocated with free() by the caller.
 **/
char *
shishi_principal_default_guess (void)
{
  const char *envuser;

  envuser = getenv ("SHISHI_USER");
  if (!envuser)
    envuser = getenv ("USER");
  if (!envuser)
    envuser = "user";

  return xstrdup (envuser);
}


/**
 * shishi_principal_default:
 * @handle: Shishi library handle create by shishi_init().
 *
 * The default principal name is the name in the environment variable
 * USER, but can be overridden by specifying the environment variable
 * SHISHI_USER.
 *
 * Return value: Returns the default principal name used in the
 * library.  (Not a copy of it, so don't modify or deallocate it.)
 **/
const char *
shishi_principal_default (Shishi * handle)
{
  if (!handle->default_principal)
    {
      char *p;
      p = shishi_principal_default_guess ();
      shishi_principal_default_set (handle, p);
      free (p);
    }

  return handle->default_principal;
}

/**
 * shishi_principal_default_set:
 * @handle: Shishi library handle create by shishi_init().
 * @principal: string with new default principal name, or NULL to
 * reset to default.
 *
 * Set the default realm used in the library.  The string is copied
 * into the library, so you can dispose of the variable immediately
 * after calling this function.
 **/
void
shishi_principal_default_set (Shishi * handle, const char *principal)
{
  if (handle->default_principal)
    free (handle->default_principal);
  if (principal)
    handle->default_principal = xstrdup (principal);
  else
    handle->default_principal = NULL;
}

/**
 * shishi_parse_name:
 * @handle: Shishi library handle create by shishi_init().
 * @name: Input principal name string, e.g. imap/mail.gnu.org@GNU.ORG.
 * @principal: newly allocated output string with principal name.
 * @realm: newly allocated output string with realm name.
 *
 * Split up principal name (e.g., "simon@JOSEFSSON.ORG") into two
 * newly allocated strings, the principal ("simon") and realm
 * ("JOSEFSSON.ORG").  If there is no realm part in NAME, REALM is set
 * to NULL.
 *
 * Return value: Returns SHISHI_INVALID_PRINCIPAL_NAME if NAME is NULL
 *   or ends with the escape character "\", or SHISHI_OK iff
 *   successful
 **/
int
shishi_parse_name (Shishi * handle, const char *name,
		   char **principal, char **realm)
{
  const char *p = name;
  const char *q;
  int escaped = 0;

  if (!name)
    return SHISHI_INVALID_PRINCIPAL_NAME;

  while (*p && (*p != '@' || escaped))
    if (escaped)
      escaped = 0;
    else if (*p++ == '\\')
      escaped = 1;

  if (escaped)
    return SHISHI_INVALID_PRINCIPAL_NAME;

  if (principal)
    {
      *principal = xstrndup (name, p - name + 1);
      (*principal)[p - name] = '\0';
    }

  if (*p)
    {
      q = ++p;

      while (*q)
	if (escaped)
	  escaped = 0;
	else if (*q++ == '\\')
	  escaped = 1;

      if (escaped)
	return SHISHI_INVALID_PRINCIPAL_NAME;

      if (realm)
	*realm = xstrdup (p);
    }
  else if (realm)
    *realm = NULL;

  return SHISHI_OK;
}

/**
 * shishi_principal_name:
 * @handle: Shishi library handle create by shishi_init().
 * @namenode: ASN.1 structure with principal in @namefield.
 * @namefield: name of field in @namenode containing principal name.
 * @out: pointer to newly allocated zero terminated string containing
 *   principal name.  May be %NULL (to only populate @outlen).
 * @outlen: pointer to length of @out on output, excluding terminating
 *   zero.  May be %NULL (to only populate @out).
 *
 * Represent principal name in ASN.1 structure as zero-terminated
 * string.  The string is allocate by this function, and it is the
 * responsibility of the caller to deallocate it.  Note that the
 * output length @outlen does not include the terminating zero.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_principal_name (Shishi * handle,
		       Shishi_asn1 namenode,
		       const char *namefield, char **out, size_t * outlen)
{
  char *format;
  size_t i, j, n;
  char *name = NULL;
  size_t namelen = 0;
  int res;

  asprintf (&format, "%s.name-string", namefield);
  res = shishi_asn1_number_of_elements (handle, namenode, format, &n);
  free (format);
  if (res != SHISHI_OK)
    return res;

  for (i = 1; i <= n; i++)
    {
      char *tmp;
      size_t tmplen;
      size_t safetmplen;

      asprintf (&format, "%s.name-string.?%d", namefield, i);
      res = shishi_asn1_read (handle, namenode, format, &tmp, &tmplen);
      free (format);
      if (res != SHISHI_OK)
	return res;

      safetmplen = tmplen;
      for (j = 0; j < tmplen; j++)
	if (tmp[j] == '@' || tmp[j] == '/' || tmp[j] == '\\')
	  safetmplen++;
      if (i < n)
	safetmplen++;

      name = xrealloc (name, namelen + safetmplen);

      for (j = 0; j < tmplen; j++)
	{
	  if (tmp[j] == '@' || tmp[j] == '/' || tmp[j] == '\\')
	    name[namelen++] = '\\';
	  name[namelen++] = tmp[j];
	}

      if (i < n)
	name[namelen++] = '/';

      free (tmp);
    }

  name = xrealloc (name, namelen + 1);
  name[namelen] = '\0';

  if (out)
    *out = name;
  else
    free (name);
  if (outlen)
    *outlen = namelen;

  return SHISHI_OK;
}

/**
 * shishi_principal_name_realm:
 * @handle: Shishi library handle create by shishi_init().
 * @namenode: ASN.1 structure with principal name in @namefield.
 * @namefield: name of field in @namenode containing principal name.
 * @realmnode: ASN.1 structure with principal realm in @realmfield.
 * @realmfield: name of field in @realmnode containing principal realm.
 * @out: pointer to newly allocated zero terminated string containing
 *   principal name.  May be %NULL (to only populate @outlen).
 * @outlen: pointer to length of @out on output, excluding terminating
 *   zero.  May be %NULL (to only populate @out).
 *
 * Represent principal name and realm in ASN.1 structure as
 * zero-terminated string.  The string is allocate by this function,
 * and it is the responsibility of the caller to deallocate it.  Note
 * that the output length @outlen does not include the terminating
 * zero.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_principal_name_realm (Shishi * handle,
			     Shishi_asn1 namenode,
			     const char *namefield,
			     Shishi_asn1 realmnode,
			     const char *realmfield,
			     char **out, size_t * outlen)
{
  char *tmp;
  size_t tmplen;
  int rc;

  rc = shishi_principal_name (handle, namenode, namefield, &tmp, &tmplen);
  if (rc != SHISHI_OK)
    return rc;

  if (realmnode == NULL && realmfield)
    {
      size_t realmfieldlen = strlen (realmfield);

      tmp = xrealloc (tmp, tmplen + 1 + realmfieldlen + 1);

      tmp[tmplen] = '@';
      memcpy (tmp + tmplen + 1, realmfield, realmfieldlen);

      tmplen += 1 + realmfieldlen;

      tmp[tmplen] = '\0';
    }
  else if (realmnode != NULL)
    {
      char *realm;
      size_t realmlen;

      rc = shishi_asn1_read (handle, realmnode, realmfield,
			     &realm, &realmlen);
      if (rc != SHISHI_OK)
	{
	  free (tmp);
	  return rc;
	}

      tmp = xrealloc (tmp, tmplen + 1 + realmlen + 1);

      tmp[tmplen] = '@';
      memcpy (tmp + tmplen + 1, realm, realmlen);

      tmplen += 1 + realmlen;

      tmp[tmplen] = '\0';

      free (realm);
    }

  *out = tmp;
  if (outlen)
    *outlen = tmplen;

  return SHISHI_OK;
}

/**
 * shishi_principal_name_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @namenode: ASN.1 structure with principal in @namefield.
 * @namefield: name of field in namenode containing principal name.
 * @name_type: type of principial, see Shishi_name_type, usually
 *             SHISHI_NT_UNKNOWN.
 * @name: zero-terminated input array with principal name.
 *
 * Set the given principal name field to given name.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_principal_name_set (Shishi * handle,
			   Shishi_asn1 namenode,
			   const char *namefield,
			   Shishi_name_type name_type, const char *name[])
{
  int res;
  char *asn1name;
  int i;

  asprintf (&asn1name, "%s.name-type", namefield);
  res = shishi_asn1_write_int32 (handle, namenode, asn1name, name_type);
  free (asn1name);
  if (res != SHISHI_OK)
    return res;

  asprintf (&asn1name, "%s.name-string", namefield);
  res = shishi_asn1_write (handle, namenode, asn1name, NULL, 0);
  free (asn1name);
  if (res != SHISHI_OK)
    return res;

  i = 1;
  while (name[i - 1])
    {
      asprintf (&asn1name, "%s.name-string", namefield);
      res = shishi_asn1_write (handle, namenode, asn1name, "NEW", 1);
      free (asn1name);
      if (res != SHISHI_OK)
	return res;

      asprintf (&asn1name, "%s.name-string.?%d", namefield, i);
      res = shishi_asn1_write (handle, namenode, asn1name, name[i - 1], 0);
      free (asn1name);
      if (res != SHISHI_OK)
	return res;

      i++;
    }

  return SHISHI_OK;
}

/**
 * shishi_principal_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @namenode: ASN.1 structure with principal in @namefield.
 * @namefield: name of field in namenode containing principal name.
 * @name: zero-terminated string with principal name on RFC 1964 form.
 *
 * Set principal name field in ASN.1 structure to given name.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_principal_set (Shishi * handle,
		      Shishi_asn1 namenode,
		      const char *namefield, const char *name)
{
  char *tmpname;
  const char **namebuf;
  char *tokptr = NULL;
  int res;
  int i;

  tmpname = xstrdup (name);
  namebuf = xmalloc (sizeof (*namebuf));

  for (i = 0;
       (namebuf[i] = strtok_r (i == 0 ? tmpname : NULL, "/", &tokptr)); i++)
    {
      namebuf = xrealloc (namebuf, (i + 2) * sizeof (*namebuf));
    }

  res = shishi_principal_name_set (handle, namenode, namefield,
				   SHISHI_NT_UNKNOWN, namebuf);
  free (namebuf);
  free (tmpname);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, _("Could not set principal name: %s\n"),
			   shishi_strerror (res));
      return res;
    }

  return SHISHI_OK;
}

/**
 * shishi_derive_default_salt:
 * @handle: shishi handle as allocated by shishi_init().
 * @name: principal name of user.
 * @salt: output variable with newly allocated salt string.
 *
 * Derive the default salt from a principal.  The default salt is the
 * concatenation of the decoded realm and principal.
 *
 * Return value: Return SHISHI_OK if successful.
 **/
int
shishi_derive_default_salt (Shishi * handle,
			    const char *name,
			    char **salt)
{
  char *principal;
  char *realm;
  int rc;

  rc = shishi_parse_name (handle, name, &principal, &realm);
  if (rc != SHISHI_OK)
    return rc;

  if (!principal || !realm)
    {
      if (realm)
	free (realm);
      if (principal)
	free (principal);
      return SHISHI_INVALID_PRINCIPAL_NAME;
    }

  *salt = xasprintf ("%s%s", realm, principal);

  free (realm);
  free (principal);

  return SHISHI_OK;
}

/**
 * shishi_server_for_local_service:
 * @handle: shishi handle as allocated by shishi_init().
 * @service: zero terminated string with name of service, e.g., "host".
 *
 * Construct a service principal (e.g., "imap/yxa.extuno.com") based
 * on supplied service name (i.e., "imap") and the system hostname as
 * returned by hostname() (i.e., "yxa.extundo.com").  The string must
 * be deallocated by the caller.
 *
 * Return value: Return newly allocated service name string.
 **/
char *
shishi_server_for_local_service (Shishi * handle, const char *service)
{
  char *hostname;
  char *server;

  hostname = xgethostname ();

  asprintf (&server, "%s/%s", service, hostname);

  free (hostname);

  return server;
}
