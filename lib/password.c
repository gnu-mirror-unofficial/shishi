/* password.c	get passwords from user
 * Copyright (C) 2002  Simon Josefsson
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

#include "internal.h"

#if defined (HAVE_TERMIOS_H)

#include <termios.h>

static int
tty_set_echo (int echo)
{
  struct termios termios_p;
  int fd = fileno (stdin);
  int rc;

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
  RETSIGTYPE
tty_echo (int signum)
{
  tty_set_echo (1);
}

RETSIGTYPE
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
shishi_prompt_password (FILE * in, char *s, int size,
			FILE * out, char *format, ...)
{
  va_list ap;
  int rc;

  va_start (ap, format);
  vfprintf (out, format, ap);
  fflush (out);
  rc = shishi_read_password (in, s, size);
  fprintf (out, "\n");

  return rc;
}
