/* error.c	error handling functions
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

#include "internal.h"

const char *
shishi_strerror_details (Shishi * handle)
{
  return handle->error ? handle->
    error :
    "Internal application error: shishi_strerror() called without an "
    "error condition";
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
  char *p;

  switch (err)
    {
    case SHISHI_OK:
      p = _("Shishi success");
      break;

    case SHISHI_MALLOC_ERROR:
      p = _("Memory allocation error in shishi library.");
      break;

    case SHISHI_BASE64_ERROR:
      p = _("Base64 encoding or decoding failed.  This usually means the "
	    "data is corrupt.");
      break;

    case SHISHI_FOPEN_ERROR:
      p = _("Could not open file.");
      break;

    case SHISHI_FCLOSE_ERROR:
      p = _("Could not close file.");
      break;

    case SHISHI_GCRYPT_ERROR:
      p = _("Internal libgcrypt error.");
      break;

    case SHISHI_NONCE_MISMATCH:
      p =
	_
	("Replay protection value (nonce) differ between request and reply.");
      break;

    case SHISHI_REALM_MISMATCH:
      p = _("Client realm value differ between request and reply.");
      break;

    case SHISHI_CNAME_MISMATCH:
      p = _("Client name value differ between request and reply.");
      break;

    case SHISHI_ASN1_ERROR:
      p = _("Error in ASN.1 data, probably due to corrupt data.");
      break;

    case SHISHI_CRYPTO_ERROR:
      p =
	_
	("Low-level cryptographic primitive failed.  This usually indicates "
	 "bad password or data corruption.");
      break;

    case SHISHI_KDC_TIMEOUT:
      p = _("Timedout talking to KDC. This usually indicates a network "
	    "or KDC address problem.");
      break;

    case SHISHI_KDC_NOT_KNOWN_FOR_REALM:
      p = _("No KDC for realm known.");
      break;

    case SHISHI_SOCKET_ERROR:
      p = _("The system call socket() failed.  This usually indicates that "
	    "your system does not support the socket type.");
      break;

    case SHISHI_BIND_ERROR:
      p = _("The system call bind() failed.  This usually indicates "
	    "insufficient permissions.");
      break;

    case SHISHI_SENDTO_ERROR:
      p = _("The system call sendto() failed.");
      break;

    case SHISHI_CLOSE_ERROR:
      p = _("The system call close() failed.");
      break;

    case SHISHI_GOT_KRBERROR:
      p = _("Server replied with an error message to request.");
      break;

    case SHISHI_INVALID_TICKETSET:
      p = _("Ticketset not initialized.  This usually indicates an internal "
	    "application error.");
      break;

    case SHISHI_TICKET_BAD_KEYTYPE:
      p = _("Keytype used to encrypt ticket doesn't match provided key. "
	    "This usually indicates an internal application error.");
      break;

    case SHISHI_APREQ_DECRYPT_FAILED:
      p = _("Could not decrypt AP-REQ using provided key. "
	    "This usually indicates an internal application error.");
      break;

    case SHISHI_TICKET_DECRYPT_FAILED:
      p = _("Could not decrypt Ticket using provided key. "
	    "This usually indicates an internal application error.");
      break;

    default:
      shishi_asprintf (&p, _("Unknown shishi error (%d)"), err);
      break;
    }

  return p;

}

void
shishi_error_clear (Shishi * handle)
{
  handle->error[0] = '\0';
}

void
shishi_error_set (Shishi * handle, const char *error)
{
  if (error)
    strncpy (handle->error, error, sizeof (handle->error));
  else
    shishi_error_clear (handle);
}

void
shishi_error_printf (Shishi * handle, char *format, ...)
{
  va_list ap;

  va_start (ap, format);

  vsnprintf (handle->error, sizeof (handle->error), format, ap);
}
