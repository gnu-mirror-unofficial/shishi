/* passwdpromptcb.c --- Self test the password prompt callback stuff.
 * Copyright (C) 2008  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

#include "utils.c"

int cb_ret = 0;

static int
prompt_password (Shishi * handle, char **s, const char *format, va_list ap)
{
  if (cb_ret == 0)
    *s = strdup ("pencil");
  return cb_ret;
}


void
test (Shishi * handle)
{
  shishi_prompt_password_func cb;
  char *passwd, *save;
  int ret;

  cb = shishi_prompt_password_callback_get (handle);
  if (cb)
    fail ("callback not null: %p\n", cb);
  else
    success ("callback is null.\n");

  shishi_prompt_password_callback_set (handle, prompt_password);

  cb = shishi_prompt_password_callback_get (handle);
  if (cb != prompt_password)
    fail ("callback not equal: %p != %p\n", cb, prompt_password);
  else
    success ("callback equal to our function.\n");

  cb_ret = SHISHI_CRYPTO_ERROR;
  save = passwd = strdup ("foo");
  ret = shishi_prompt_password (handle, &passwd, "Enter %s: ", "password");
  if (ret != cb_ret)
    fail ("callback return mismatch: %d != %d\n", ret, cb_ret);
  else
    success ("invoke callback successfully with non-zero return\n");

  if (passwd != save)
    fail ("callback messed with password: %s != %s\n", passwd, save);

  free (save);

  cb_ret = 0;
  ret = shishi_prompt_password (handle, &passwd, "Enter %s: ", "password");
  if (ret != cb_ret)
    fail ("callback return mismatch: %d != %d\n", ret, cb_ret);
  else
    success ("invoke callback successfully with zero return code\n");

  if (strcmp (passwd, "pencil") != 0)
    fail ("callback returned bad password: %s\n", passwd);
  else
    success ("callback returned correct password: %s\n", passwd);

  free (passwd);
}
