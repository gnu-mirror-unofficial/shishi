/* error.c	error handling functions
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

const char *
shishi_strerror_details (Shishi * handle)
{
  return handle->error ? handle->
    error :
    "Internal application error: shishi_strerror() called without an error condition";
}

/**
 * shishi_strerror:
 * @err: shishi error code
 * 
 * Return value: Returns a pointer to a statically allocated string
 * containing a description of the error with the error value
 * @var{err}.  This string can be used to output a diagnostic message
 * to the user.
 **/
const char *
shishi_strerror (int err)
{
  const char *p;

  switch (err)
    {
    case SHISHI_OK:
      p = _("Shishi success");
      break;

    case SHISHI_MALLOC_ERROR:
      p = _("Memory allocation error in shishi library");
      break;

    case SHISHI_FOPEN_ERROR:
      p = _("Could not open file");
      break;

    case SHISHI_FCLOSE_ERROR:
      p = _("Could not close file");
      break;

    case SHISHI_GCRYPT_ERROR:
      p = _("Internal libgcrypt error");
      break;

    case SHISHI_NONCE_MISMATCH:
      p =
	_("Replay protection value (nonce) differ between request and reply");
      break;

    case SHISHI_REALM_MISMATCH:
      p = _("Client realm value differ between request and reply");
      break;

    case SHISHI_CNAME_MISMATCH:
      p = _("Client name value differ between request and reply");
      break;

    case SHISHI_ASN1_ERROR:
      p = _("Error in ASN.1 data, probably due to corrupt data");
      break;

    case SHISHI_CRYPTO_ERROR:
      p = _("Low-level cryptographic primitive failed.  This usually indicates bad password or data corruption.");
      break;

    default:
      shishi_asprintf(&p, _("Unknown shishi error (%d)"), err);
      break;
    }

  return p;

}

void
shishi_error_set (Shishi * handle, const char *error)
{
  strncpy (handle->error, error, sizeof (handle->error));
}

void
shishi_error_printf (Shishi * handle, char *format, ...)
{
  va_list ap;

  va_start (ap, format);

  vsnprintf (handle->error, sizeof (handle->error), format, ap);
}
