/* pki.c --- Public Key Infrastructure support functions for Shishi.
 * Copyright (C) 2002, 2003, 2004, 2007  Simon Josefsson
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

#include "internal.h"

#define X509CA_FILE "client.ca"
#define X509KEY_FILE "client.key"
#define X509CERT_FILE "client.certs"

/**
 * shishi_x509ca_default_file_guess:
 * @handle: Shishi library handle create by shishi_init().
 *
 * Guesses the default X.509 CA certificate filename; it is
 * $HOME/.shishi/client.ca.
 *
 * Return value: Returns default X.509 client certificate filename as
 *   a string that has to be deallocated with free() by the caller.
 **/
char *
shishi_x509ca_default_file_guess (Shishi * handle)
{
  return shishi_cfg_userdirectory_file (handle, X509CA_FILE);
}

/**
 * shishi_x509ca_default_file_set:
 * @handle: Shishi library handle create by shishi_init().
 * @x509cafile: string with new default x509 client certificate file name,
 *   or NULL to reset to default.
 *
 * Set the default X.509 CA certificate filename used in the library.
 * The certificate is used during TLS connections with the KDC to
 * authenticate the KDC.  The string is copied into the library, so
 * you can dispose of the variable immediately after calling this
 * function.
 **/
void
shishi_x509ca_default_file_set (Shishi * handle, const char *x509cafile)
{
  if (handle->x509cafile)
    free (handle->x509cafile);
  if (x509cafile)
    handle->x509cafile = xstrdup (x509cafile);
  else
    handle->x509cafile = shishi_x509ca_default_file_guess (handle);
}

/**
 * shishi_x509ca_default_file:
 * @handle: Shishi library handle create by shishi_init().
 *
 * Get filename for default X.509 CA certificate.
 *
 * Return value: Returns the default X.509 CA certificate filename
 *   used in the library.  The certificate is used during TLS
 *   connections with the KDC to authenticate the KDC.  The string is
 *   not a copy, so don't modify or deallocate it.
 **/
const char *
shishi_x509ca_default_file (Shishi * handle)
{
  if (!handle->x509cafile)
    shishi_x509ca_default_file_set (handle, NULL);

  return handle->x509cafile;
}

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
 * @x509certfile: string with new default x509 client certificate file name,
 *   or NULL to reset to default.
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
 * Get filename for default X.509 certificate.
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
 * Get filename for default X.509 key.
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
