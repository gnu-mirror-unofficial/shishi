/* pki.c --- Public Key Infrastructure support functions for Shishi.
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
 * shishi_x509cert_default_file_guess:
 * @handle: Shishi library handle create by shishi_init().
 *
 * Guesses the default X.509 client certificate filename; it is
 * $HOME/.shishi/client.certs.
 *
 * Return value: Returns default X.509 client certificate filename as
 *   a string that has to be deallocated with free() by the caller.
 **/
char *
shishi_x509cert_default_file_guess (Shishi * handle)
{
  return shishi_cfg_userdirectory_file (handle, X509CERT_FILE);
}

/**
 * shishi_x509cert_default_file_set:
 * @handle: Shishi library handle create by shishi_init().
 * @tktsfile: string with new default x509 client certificate file name, or
 *   NULL to reset to default.
 *
 * Set the default X.509 client certificate filename used in the
 * library.  The certificate is used during TLS connections with the
 * KDC to authenticate the client.  The string is copied into the
 * library, so you can dispose of the variable immediately after
 * calling this function.
 **/
void
shishi_x509cert_default_file_set (Shishi * handle, const char *x509certfile)
{
  if (handle->x509certfile)
    free (handle->x509certfile);
  if (x509certfile)
    handle->x509certfile = xstrdup (x509certfile);
  else
    handle->x509certfile = shishi_x509cert_default_file_guess (handle);
}

/**
 * shishi_x509cert_default_file:
 * @handle: Shishi library handle create by shishi_init().
 *
 * Return value: Returns the default X.509 client certificate filename
 *   used in the library.  The certificate is used during TLS
 *   connections with the KDC to authenticate the client.  The string is
 *   not a copy, so don't modify or deallocate it.
 **/
const char *
shishi_x509cert_default_file (Shishi * handle)
{
  if (!handle->x509certfile)
    shishi_x509cert_default_file_set (handle, NULL);

  return handle->x509certfile;
}

/**
 * shishi_x509key_default_file_guess:
 * @handle: Shishi library handle create by shishi_init().
 *
 * Guesses the default X.509 client key filename; it is
 * $HOME/.shishi/client.key.
 *
 * Return value: Returns default X.509 client key filename as
 *   a string that has to be deallocated with free() by the caller.
 **/
char *
shishi_x509key_default_file_guess (Shishi * handle)
{
  return shishi_cfg_userdirectory_file (handle, X509KEY_FILE);
}

/**
 * shishi_x509key_default_file_set:
 * @handle: Shishi library handle create by shishi_init().
 * @x509keyfile: string with new default x509 client key file name, or
 *   NULL to reset to default.
 *
 * Set the default X.509 client key filename used in the library.  The
 * key is used during TLS connections with the KDC to authenticate the
 * client.  The string is copied into the library, so you can dispose
 * of the variable immediately after calling this function.
 **/
void
shishi_x509key_default_file_set (Shishi * handle, const char *x509keyfile)
{
  if (handle->x509keyfile)
    free (handle->x509keyfile);
  if (x509keyfile)
    handle->x509keyfile = xstrdup (x509keyfile);
  else
    handle->x509keyfile = shishi_x509key_default_file_guess (handle);
}

/**
 * shishi_x509key_default_file:
 * @handle: Shishi library handle create by shishi_init().
 *
 * Return value: Returns the default X.509 client key filename
 *   used in the library.  The key is used during TLS
 *   connections with the KDC to authenticate the client.  The string is
 *   not a copy, so don't modify or deallocate it.
 **/
const char *
shishi_x509key_default_file (Shishi * handle)
{
  if (!handle->x509keyfile)
    shishi_x509key_default_file_set (handle, NULL);

  return handle->x509keyfile;
}
