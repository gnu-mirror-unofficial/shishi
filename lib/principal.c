/* principal.c	get and set default principal
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
    return strdup (pw->pw_name);
  else
    return strdup ("user");
}


/**
 * shishi_principal_default:
 * @handle: Shishi library handle create by shishi_init().
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
    handle->default_principal = strdup (principal);
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
    *realm = strdup (shishi_realm_default (handle));

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

int
shishi_principal_name_get (Shishi * handle,
			   Shishi_asn1 namenode,
			   const char *namefield, char *out, size_t * outlen)
{
  int res;
  char format[BUFSIZ];
  size_t totlen = 0;
  int len;
  int i, j, n;

  sprintf (format, "%s.name-string", namefield);
  res = shishi_asn1_number_of_elements (handle, namenode, format, &n);
  if (res != SHISHI_OK)
    return res;

  totlen = 0;
  for (i = 1; i <= n; i++)
    {
      len = *outlen - totlen;
      sprintf (format, "%s.name-string.?%d", namefield, i);
      res = shishi_asn1_read (handle, namenode, format, &out[totlen], &len);
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

int
shishi_principal_name_realm_get (Shishi * handle,
				 Shishi_asn1 namenode,
				 const char *namefield,
				 Shishi_asn1 realmnode,
				 const char *realmfield,
				 char *out, size_t * outlen)
{
  int res;
  size_t totlen = 0;
  int len;

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
      res = shishi_asn1_read (handle, realmnode, realmfield,
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
  char *buf, *asn1name;
  int i;

  asprintf (&buf, "%d", name_type);
  asprintf (&asn1name, "%s.name-type", namefield);
  res = shishi_asn1_write (handle, namenode, asn1name, buf, 0);
  free (asn1name);
  free (buf);
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

  tmpname = strdup (name);
  if (tmpname == NULL)
    return SHISHI_MALLOC_ERROR;

  namebuf = malloc (sizeof (*namebuf));
  if (namebuf == NULL)
    return SHISHI_MALLOC_ERROR;

  for (i = 0;
       (namebuf[i] = strtok_r (i == 0 ? tmpname : NULL, "/", &tokptr)); i++)
    {
      namebuf = realloc (namebuf, (i + 2) * sizeof (*namebuf));
      if (namebuf == NULL)
	return SHISHI_MALLOC_ERROR;
    }

  res = shishi_principal_name_set (handle, namenode, namefield,
				   SHISHI_NT_UNKNOWN, namebuf);
  if (res != SHISHI_OK)
    {
      shishi_error_printf (handle, _("Could not set principal name: %s\n"),
			   shishi_strerror (res));
      return res;
    }

  free (namebuf);
  free (tmpname);

  return SHISHI_OK;
}

char *
shishi_server_for_local_service (Shishi * handle, const char *service)
{
  char buf[HOST_NAME_MAX];
  int ret;

  strcpy (buf, service);
  strcat (buf, "/");

  ret = gethostname (&buf[strlen (service) + 1],
		     sizeof (buf) - strlen (service) - 1);
  buf[sizeof (buf) - 1] = '\0';

  if (ret != 0)
    strcpy (&buf[strlen (service) + 1], "localhost");

  return xstrdup (buf);
}
