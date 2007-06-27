/* error.c --- Error handling functions for the Shisa library.
 * Copyright (C) 2002, 2003, 2004, 2006, 2007  Simon Josefsson
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#include "info.h"

struct shisa_error_msgs
{
  int errorcode;
  const char *message;
};

static const struct shisa_error_msgs _shisa_error_messages[] = {
  {SHISA_OK,
   N_("Shisa success")},
  {SHISA_INIT_ERROR,
   N_("Shisa could not be initialized.")},
  {SHISA_CFG_NO_FILE,
   N_("The Shisa configuration file does not exist.")},
  {SHISA_CFG_IO_ERROR,
   N_("File I/O error for Shisa configuration file.")},
  {SHISA_CFG_SYNTAX_ERROR,
   N_("Syntax error in Shisa configuration token.")},
  {SHISA_OPEN_ERROR,
   N_("Shisa database could not be opened.")},
  {SHISA_ENUMERATE_REALM_ERROR,
   N_("Error enumerating realms in database.")},
  {SHISA_ENUMERATE_PRINCIPAL_ERROR,
   N_("Error enumerating principals in database.")},
  {SHISA_ENUMERATE_KEY_ERROR,
   N_("Error enumerating keys in database.")},
  {SHISA_NO_REALM,
   N_("Supplied realm does not exist.")},
  {SHISA_NO_PRINCIPAL,
   N_("Supplied principal does not exist.")},
  {SHISA_NO_KEY,
   N_("Principal is not associated with any matching key.")},
  {SHISA_FIND_ERROR,
   N_("Error finding principal.")},
  {SHISA_ADD_REALM_EXISTS,
   N_("Tried to add a realm that already exist.")},
  {SHISA_ADD_REALM_ERROR,
   N_("Error adding realm to database.")},
  {SHISA_REMOVE_REALM_NONEMPTY,
   N_("Tried to remove a non-empty realm.")},
  {SHISA_REMOVE_REALM_ERROR,
   N_("Error removing realm from database.")},
  {SHISA_ADD_PRINCIPAL_EXISTS,
   N_("Tried to add a principal that already exist.")},
  {SHISA_ADD_PRINCIPAL_ERROR,
   N_("Error adding principal to database.")},
  {SHISA_REMOVE_PRINCIPAL_ERROR,
   N_("Error removing principal from database.")},
  {SHISA_ADD_KEY_ERROR,
   N_("Error adding key to principal.")},
  {SHISA_REMOVE_KEY_ERROR,
   N_("Error removing key from principal.")},
  {SHISA_MULTIPLE_KEY_MATCH,
   N_("More than one key match given search criteria.")}
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

  va_start (ap, format);
  vasprintf (&out, format, ap);

  fprintf (stderr, _("shisa: %s\n"), out);

  free (out);
  va_end (ap);
}
