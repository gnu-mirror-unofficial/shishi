/* error.c --- Error handling functions for the Shisa library.
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

struct shisa_error_msgs
{
  int errorcode;
  char *message;
};

static struct shisa_error_msgs _shisa_error_messages[] = {
  {SHISA_OK, "Shisa success"},
  {SHISA_INIT_ERROR, "Shisa could not be initialized."},
  {SHISA_CFG_NO_FILE, "The Shisa configuration file does not exist."},
  {SHISA_CFG_IO_ERROR, "File I/O error for Shisa configuration file."},
  {SHISA_CFG_SYNTAX_ERROR, "Syntax error in Shisa configuration token."},
  {SHISA_DB_OPEN_ERROR, "Shisa database could not be opened."},
};

/**
 * shisa_strerror:
 * @err: shisa error code
 *
 * Return value: Returns a pointer to a statically allocated string
 * containing a description of the error with the error value @err.
 * This string can be used to output a diagnostic message to the user.
 **/
const char *
shisa_strerror (int err)
{
  char *p = NULL;
  size_t i;

  for (i = 0; i < sizeof (_shisa_error_messages) /
	 sizeof (_shisa_error_messages[0]); i++)
    if (_shisa_error_messages[i].errorcode == err)
	return _(_shisa_error_messages[i].message);

  return _("Unknown Shisa error");
}

/**
 * shisa_info:
 * @dbh: Shisa library handle created by shisa().
 * @format: printf style format string.
 * @...: print style arguments.
 *
 * Print informational message to standard error.
 **/
void
shisa_info (Shisa * dbh, const char *format, ...)
{
  va_list ap;
  char *out;
  int type;

  va_start (ap, format);
  vasprintf (&out, format, ap);

  fprintf (stderr, "shisa: %s\n", out);

  free (out);
  va_end (ap);
}
