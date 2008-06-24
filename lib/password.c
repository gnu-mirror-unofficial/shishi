/* password.c --- Get passwords from user.
 * Copyright (C) 2002, 2003, 2004, 2005, 2007, 2008  Simon Josefsson
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

/* XXX? zeroize password */

#include "internal.h"

#include "getpass.h"

#ifdef HAVE_LIBIDN
# include <stringprep.h>
#endif

/**
 * shishi_prompt_password_callback_set:
 * @handle: shishi handle as allocated by shishi_init().
 * @cb: function pointer to application password callback, a
 *   #shishi_prompt_password_func type.
 *
 * Set a callback function that will be used by
 * shishi_prompt_password() to query the user for a password.  The
 * function pointer can be retrieved using
 * shishi_prompt_password_callback_get().
 *
 * The @cb function should follow the %shishi_prompt_password_func prototype:
 *
 * int prompt_password (Shishi * @handle, char **@s,
 * const char *@format, va_list @ap);
 *
 * If the function returns 0, the @s variable should contain a newly
 * allocated string with the password read from the user.
 **/
void
shishi_prompt_password_callback_set (Shishi * handle,
				     shishi_prompt_password_func cb)
{
  handle->prompt_passwd = cb;
}

/**
 * shishi_prompt_password_callback_get:
 * @handle: shishi handle as allocated by shishi_init().
 *
 * Get the application password prompt function callback as set by
 * shishi_prompt_password_callback_set().
 *
 * Returns: Returns the callback, a #shishi_prompt_password_func type,
 *   or %NULL.
 **/
shishi_prompt_password_func
shishi_prompt_password_callback_get (Shishi * handle)
{
  return handle->prompt_passwd;
}

/**
 * shishi_prompt_password:
 * @handle: shishi handle as allocated by shishi_init().
 * @s: pointer to newly allocated output string with read password.
 * @format: printf(3) style format string.
 * @...: printf(3) style arguments.
 *
 * Format and print a prompt, and read a password from user.  The
 * password is possibly converted (e.g., converted from Latin-1 to
 * UTF-8, or processed using Stringprep profile) following any
 * "stringprocess" keywords in configuration files.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_prompt_password (Shishi * handle, char **s, const char *format, ...)
{
  char *p;
  va_list ap;

  if (handle->prompt_passwd)
    {
      int ret;
      va_start (ap, format);
      ret = handle->prompt_passwd (handle, s, format, ap);
      va_end (ap);

      return ret;
    }

#ifdef HAVE_LIBIDN
  if (VERBOSE (handle))
    {
      printf ("Libstringprep thinks your locale is `%s'.\n",
	      stringprep_locale_charset ());
    }
#endif

  va_start (ap, format);
  vprintf (format, ap);
  fflush (stdout);
  va_end (ap);

  p = getpass ("");

  *s = xstrdup (p);

  printf ("\n");

  if (VERBOSENOISE (handle))
    {
      size_t i;
      printf ("Read password (length %d): ", strlen (*s));
      for (i = 0; i < strlen (*s); i++)
	printf ("%02x ", (*s)[i] & 0xFF);
      printf ("\n");
    }

  if (handle->stringprocess
      && strcasecmp (handle->stringprocess, "none") != 0)
#ifdef HAVE_LIBIDN
    {
      if (strcasecmp (handle->stringprocess, "stringprep") == 0)
	p = stringprep_locale_to_utf8 (*s);
      else
	p = stringprep_convert (*s, handle->stringprocess,
				stringprep_locale_charset ());

      if (p)
	{
	  free (*s);
	  *s = p;
	}
      else
	shishi_warn (handle, "Charset conversion of password failed");

      if (VERBOSENOISE (handle))
	{
	  size_t i;
	  printf ("Password converted to %s (length %d): ",
		  strcasecmp (handle->stringprocess, "stringprep") == 0 ?
		  "UTF-8" : handle->stringprocess, strlen (*s));
	  for (i = 0; i < strlen (*s); i++)
	    printf ("%02x ", (*s)[i] & 0xFF);
	  printf ("\n");
	}

      if (strcasecmp (handle->stringprocess, "stringprep") == 0)
	{
	  int rc;

	  rc = stringprep_profile (*s, &p, "SASLprep", 0);
	  if (rc == SHISHI_OK)
	    {
	      free (*s);
	      *s = p;
	    }
	  else
	    shishi_warn (handle, "Stringprep conversion of password failed");

	  if (VERBOSENOISE (handle))
	    {
	      size_t i;
	      printf ("Stringprep'ed password (length %d): ", strlen (*s));
	      for (i = 0; i < strlen (*s); i++)
		printf ("%02x ", (*s)[i] & 0xFF);
	      printf ("\n");
	    }

	}
    }
#else
    shishi_warn (handle, "Password string processing (%s) disabled",
		 handle->stringprocess);
#endif

  return SHISHI_OK;
}
