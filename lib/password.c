/* password.c	get passwords from user
 * Copyright (C) 2002  Simon Josefsson
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
#include <stringprep.h>
#include <stringprep_kerberos5.h>

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

int
shishi_read_password (FILE * fh, char *s, int size)
{
  int rc;

  rc = tty_set_echo (0);
  if (rc != SHISHI_OK)
    return rc;

#ifdef HAVE_SIGNAL
  signal (SIGQUIT, tty_echo);
  signal (SIGCONT, tty_noecho);
#endif

  fgets (s, size, fh);
  s[strlen (s) - 1] = '\0';

#ifdef HAVE_SIGNAL
  signal (SIGQUIT, SIG_DFL);
  signal (SIGCONT, SIG_DFL);
#endif

  rc = tty_set_echo (1);
  if (rc != SHISHI_OK)
    return rc;

  return SHISHI_OK;
}

int
shishi_prompt_password_raw (FILE * in, char *s, int size,
			    FILE * out, char *format, ...)
{
  va_list ap;
  int rc;

  va_start (ap, format);
  vfprintf (out, format, ap); fflush (out);
  va_end (ap);

  rc = shishi_read_password (in, s, size);

  fprintf (out, "\n");

  return rc;
}

int
shishi_prompt_password (Shishi *handle,
			FILE * in, char *s, int size,
			FILE * out, char *format, ...)
{
  char *p;
  va_list ap;
  int rc;

  if (VERBOSE(handle))
    {
      printf("Libstringprep thinks your locale is `%s'.\n",
	     stringprep_locale_charset());
    }

  va_start (ap, format);
  vfprintf (out, format, ap); fflush (out);
  va_end (ap);

  rc = shishi_read_password (in, s, size);

  fprintf (out, "\n");

  if (rc != SHISHI_OK)
    return rc;

  if (VERBOSE(handle))
    {
      int i;
      printf("Read password (length %d): ", strlen(s));
      for (i=0; i < strlen(s); i++)
	printf("%02x ", s[i] & 0xFF);
      printf("\n");
    }

  if (handle->stringprocess && strcasecmp(handle->stringprocess, "none") != 0)
    {
      if (strcasecmp(handle->stringprocess, "stringprep") == 0)
	p = stringprep_locale_to_utf8 (s);
      else
	p = stringprep_convert (s, handle->stringprocess,
				stringprep_locale_charset ());

      if (p)
	{
	  strncpy(s, p, size);
	  s[size-1] = '\0';
	  free(p);
	}

      if (VERBOSE(handle))
	{
	  int i;
	  printf("Password converted to %s (length %d): ",
		 strcasecmp(handle->stringprocess, "stringprep") == 0 ?
		 "UTF-8" : handle->stringprocess, strlen(s));
	  for (i=0; i < strlen(s); i++)
	    printf("%02x ", s[i] & 0xFF);
	  printf("\n");
	}

      if (strcasecmp(handle->stringprocess, "stringprep") == 0)
	{
	  rc = stringprep_kerberos5(s, size);
	  if (rc != SHISHI_OK)
	    return rc;

	  if (VERBOSE(handle))
	    {
	      int i;
	      printf("Stringprep'ed password (length %d): ", strlen(s));
	      for (i=0; i < strlen(s); i++)
		printf("%02x ", s[i] & 0xFF);
	      printf("\n");
	    }

	}
    }

  return SHISHI_OK;
}
