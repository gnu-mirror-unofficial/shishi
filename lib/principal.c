/* principal.c --- Get and set default principal.
 * Copyright (C) 2002, 2003, 2004  Simon Josefsson
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
 * shishi_principal_default_guess:
 *
 * Guesses a principal using getpwuid(getuid)), or if it fails, the
 * string "user".
 *
 * Return value: Returns guessed default principal for user as a string that
 * has to be deallocated with free() by the caller.
 **/
char *
shishi_principal_default_guess (void)
{
  uid_t uid;
  struct passwd *pw;

  uid = getuid ();
  pw = getpwuid (uid);

  if (pw)
    return xstrdup (pw->pw_name);
  else
    return xstrdup ("user");
}


/**
 * shishi_principal_default:
 * @handle: Shishi library handle create by shishi_init().
 *
 * The default principal name is the name returned from
 * getpwuid(getuid) but can be overridden by specifying the
 * environment variable SHISHI_USER.
 *
 * Return value: Returns the default principal name used in the
 * library.  (Not a copy of it, so don't modify or deallocate it.)
 **/
const char *
shishi_principal_default (Shishi * handle)
{
  char *envuser;

  envuser = getenv ("SHISHI_USER");
  if (envuser)
    return envuser;

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
    *realm = xstrdup (shishi_realm_default (handle));

  return SHISHI_OK;
}

/*
  2.1.1. Kerberos Principal Name Form

  This name form shall be represented by the Object Identifier {iso(1)
  member-body(2) United States(840) mit(113554) infosys(1) gssapi(2)
  krb5(2) krb5_name(1)}.  The recommended symbolic name for this type
  is "GSS_KRB5_NT_PRINCIPAL_NAME".

  This name type corresponds to the single-string representation of a
  Kerberos name.  (Within the MIT Kerberos V5 implementation, such
  names are parseable with the krb5_parse_name() function.)  The
  elements included within this name representation are as follows,
  proceeding from the beginning of the string:

  (1) One or more principal name components; if more than one
  principal name component is included, the components are
  separated by `/`.  Arbitrary octets may be included within
  principal name components, with the following constraints and
  special considerations:

  (1a) Any occurrence of the characters `@` or `/` within a
  name component must be immediately preceded by the `\`
  quoting character, to prevent interpretation as a component
  or realm separator.

  (1b) The ASCII newline, tab, backspace, and null characters
  may occur directly within the component or may be
  represented, respectively, by `\n`, `\t`, `\b`, or `\0`.

  (1c) If the `\` quoting character occurs outside the contexts
  described in (1a) and (1b) above, the following character is
  interpreted literally.  As a special case, this allows the
  doubled representation `\\` to represent a single occurrence
  of the quoting character.

  (1d) An occurrence of the `\` quoting character as the last
  character of a component is illegal.

  (2) Optionally, a `@` character, signifying that a realm name
  immediately follows. If no realm name element is included, the
  local realm name is assumed.  The `/` , `:`, and null characters
  may not occur within a realm name; the `@`, newline, tab, and
  backspace characters may be included using the quoting
  conventions described in (1a), (1b), and (1c) above.
*/

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

int
shishi_principal_name_get (Shishi * handle,
			   Shishi_asn1 namenode,
			   const char *namefield, char *out, size_t * outlen)
{
  int res;
  char *format;
  size_t totlen = 0;
  size_t i, j, n, len;

  /* FIXME: allocate output instead of writing inline */

  asprintf (&format, "%s.name-string", namefield);
  res = shishi_asn1_number_of_elements (handle, namenode, format, &n);
  free (format);
  if (res != SHISHI_OK)
    return res;

  totlen = 0;
  for (i = 1; i <= n; i++)
    {
      len = *outlen - totlen;
      asprintf (&format, "%s.name-string.?%d", namefield, i);
      res =
	shishi_asn1_read_inline (handle, namenode, format, &out[totlen],
				 &len);
      free (format);
      if (res != SHISHI_OK)
	return res;

      for (j = 0; j < len; j++)
	{
	  if (out[totlen] == '@' || out[totlen] == '/' || out[totlen] == '\\')
	    {
	      if (totlen + strlen ("\\") > *outlen)
		return SHISHI_TOO_SMALL_BUFFER;
	      out[totlen + 1] = out[totlen];
	      out[totlen] = '\\';
	      len++;
	      totlen++;
	      j++;
	    }
	  totlen++;
	}

      if (i < n)
	{
	  if (totlen + strlen ("/") > *outlen)
	    return SHISHI_TOO_SMALL_BUFFER;
	  out[totlen] = '/';
	  totlen++;
	}
    }

  *outlen = totlen;

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

      rc = shishi_asn1_read (handle, realmnode, realmfield, &realm, &realmlen);
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
    }

  *out = tmp;
  *outlen = tmplen;

  return SHISHI_OK;
}

int
shishi_principal_name_realm_get (Shishi * handle,
				 Shishi_asn1 namenode,
				 const char *namefield,
				 Shishi_asn1 realmnode,
				 const char *realmfield,
				 char *out, size_t * outlen)
{
  int res;
  size_t totlen = 0, len;

  /* FIXME: allocate output instead of writing inline */

  totlen = *outlen;
  res = shishi_principal_name_get (handle, namenode, namefield, out, &totlen);
  if (res != SHISHI_OK)
    return res;

  if (realmnode == NULL && realmfield)
    {
      if (totlen + strlen ("@") + strlen (realmfield) > *outlen)
	return SHISHI_TOO_SMALL_BUFFER;

      memcpy (out + totlen, "@", strlen ("@"));
      totlen += strlen ("@");
      memcpy (out + totlen, realmfield, strlen (realmfield));
      totlen += strlen (realmfield);
    }
  else if (realmnode != NULL)
    {
      if (totlen + strlen ("@") > *outlen)
	return SHISHI_TOO_SMALL_BUFFER;

      memcpy (out + totlen, "@", strlen ("@"));
      totlen += strlen ("@");

      len = *outlen - totlen;
      res = shishi_asn1_read_inline (handle, realmnode, realmfield,
				     &out[totlen], &len);
      if (res == SHISHI_ASN1_NO_ELEMENT)
	totlen--;
      else if (res != SHISHI_OK)
	return res;
      else
	totlen += len;
    }

  *outlen = totlen;

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
  char *tokptr;
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
