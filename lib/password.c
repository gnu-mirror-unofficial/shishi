/* password.c	get passwords from user
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

/* XXX? zeroize password */

#include "internal.h"

#ifdef WITH_STRINGPREP
#include <stringprep.h>
#endif

#if defined (HAVE_TERMIOS_H)

#include <termios.h>

static int
tty_set_echo (int echo)
{
  struct termios termios_p;
  int fd = fileno (stdin);

  if (tcgetattr (fd, &termios_p) != 0)
    return SHISHI_TTY_ERROR;

  if (echo)
    termios_p.c_lflag |= ECHO;
  else
    termios_p.c_lflag &= ~ECHO;

  if (tcsetattr (fd, TCSANOW, &termios_p) != 0)
    return SHISHI_TTY_ERROR;

  return SHISHI_OK;
}

#else

mail simon @ josefsson.org and tell what system this is
#endif
static RETSIGTYPE
tty_echo (int signum)
{
  tty_set_echo (1);
}

static RETSIGTYPE
tty_noecho (int signum)
{
  tty_set_echo (0);
}

static int
read_password (char **s)
{
  char buf[BUFSIZ];
  int rc;

  rc = tty_set_echo (0);
  if (rc != SHISHI_OK)
    return rc;

#ifdef HAVE_SIGNAL
  signal (SIGQUIT, tty_echo);
  signal (SIGCONT, tty_noecho);
#endif

  fgets (buf, sizeof (buf), stdin);
  buf[strlen (buf) - 1] = '\0';

  *s = strdup (buf);

#ifdef HAVE_SIGNAL
  signal (SIGQUIT, SIG_DFL);
  signal (SIGCONT, SIG_DFL);
#endif

  rc = tty_set_echo (1);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

/**
 * shishi_prompt_password:
 * @handle: shishi handle as allocated by shishi_init().
 * @s: pointer to newly allocated output string with read password.
 * @format: printf(3) style format string.
 * @...: printf(3) style arguments.
 *
 * Format and print a prompt to stdout, and read a password from
 * stdint.  The password is possibly converted (e.g., converted from
 * Latin-1 to UTF-8, or processed using Stringprep profile) following
 * any 'stringprocess' keywords in configuration files.
 *
 * Return value: Returns SHISHI_OK iff successful.
 **/
int
shishi_prompt_password (Shishi * handle, char **s, const char *format, ...)
{
  char *p;
  va_list ap;
  int rc;

#ifdef WITH_STRINGPREP
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

  rc = read_password (s);

  printf ("\n");

  if (rc != SHISHI_OK)
    return rc;

  if (VERBOSENOICE (handle))
    {
      size_t i;
      printf ("Read password (length %d): ", strlen (*s));
      for (i = 0; i < strlen (*s); i++)
	printf ("%02x ", (*s)[i] & 0xFF);
      printf ("\n");
    }

  if (handle->stringprocess
      && strcasecmp (handle->stringprocess, "none") != 0)
#ifdef WITH_STRINGPREP
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

      if (VERBOSENOICE (handle))
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
	  rc = stringprep_profile (*s, &p, "SASLprep", 0);
	  if (rc == SHISHI_OK)
	    {
	      free (*s);
	      *s = p;
	    }
	  else
	    shishi_warn (handle, "Stringprep conversion of password failed");

	  if (VERBOSENOICE (handle))
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
