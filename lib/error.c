/* error.c	error handling functions
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

const char *
shishi_strerror_details (Shishi * handle)
{
  return handle->error ? handle->
    error :
    "Internal application error: shishi_strerror() called without an "
    "error condition";
}

struct shishi_error_msgs
{
  int errorcode;
  char *message;
};

struct shishi_error_msgs _shishi_error_messages[] = {
  { SHISHI_OK,
    "Shishi success" },
  { SHISHI_ASN1_ERROR,
    "Error in ASN.1 data, probably due to corrupt data." },
  { SHISHI_FOPEN_ERROR,
    "Could not open file." },
  { SHISHI_FCLOSE_ERROR,
    "Could not close file." },
  { SHISHI_MALLOC_ERROR,
    "Memory allocation error in shishi library." },
  { SHISHI_BASE64_ERROR,
    "Base64 encoding or decoding failed. Data corrupt?" },
  { SHISHI_REALM_MISMATCH,
    "Client realm value differ between request and reply." },
  { SHISHI_CNAME_MISMATCH,
    "Client name value differ between request and reply." },
  { SHISHI_NONCE_MISMATCH,
    "Replay protection value (nonce) differ between request and reply." },
  { SHISHI_TICKET_BAD_KEYTYPE,
    "Keytype used to encrypt ticket doesn't match provided key. "
    "This usually indicates an internal application error." },
  { SHISHI_CRYPTO_INTERNAL_ERROR,
    "Internal error in low-level crypto routines." },
  { SHISHI_CRYPTO_ERROR,
    "Low-level cryptographic primitive failed.  This usually indicates "
    "bad password or data corruption." },
  { SHISHI_KDC_TIMEOUT,
    "Timedout talking to KDC. This usually indicates a network "
    "or KDC address problem." },
  { SHISHI_KDC_NOT_KNOWN_FOR_REALM,
    "No KDC for realm known." },
  { SHISHI_SOCKET_ERROR,
    "The system call socket() failed.  This usually indicates that "
    "your system does not support the socket type." },
  { SHISHI_BIND_ERROR,
    "The system call bind() failed.  This usually indicates "
    "insufficient permissions." },
  { SHISHI_SENDTO_ERROR,
    "The system call sendto() failed." },
  { SHISHI_CLOSE_ERROR,
    "The system call close() failed." },
  { SHISHI_GOT_KRBERROR,
    "Server replied with an error message to request." },
  { SHISHI_INVALID_TKTS,
    "Ticketset not initialized.  This usually indicates an internal "
    "application error." },
  { SHISHI_APREQ_DECRYPT_FAILED,
    "Could not decrypt AP-REQ using provided key. "
    "This usually indicates an internal application error." },
  { SHISHI_TICKET_DECRYPT_FAILED,
    "Could not decrypt Ticket using provided key. "
    "This usually indicates an internal application error." },
  { -1, NULL }
};

/**
 * shishi_strerror:
 * @err: shishi error code
 *
 * Return value: Returns a pointer to a statically allocated string
 * containing a description of the error with the error value @err.
 * This string can be used to output a diagnostic message to the user.
 **/
const char *
shishi_strerror (int err)
{
  char *p = NULL;
  size_t i;

  for (i = 0; _shishi_error_messages[i].errorcode != -1; i++)
    if (i == _shishi_error_messages[i].errorcode)
      {
	p = _(_shishi_error_messages[i].message);
	break;
      }

  if (!p)
    /* XXX mem leak */
    asprintf(&p, _("Unknown shishi error: %d"), err);

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
    {
      strncpy (handle->error, error, sizeof (handle->error));

      if (VERBOSE (handle))
	puts (handle->error);
    }
  else
    shishi_error_clear (handle);
}

void
shishi_error_printf (Shishi * handle, char *format, ...)
{
  va_list ap;
  char *s;

  va_start (ap, format);

  vasprintf (&s, format, ap);
  strncpy (handle->error, s, sizeof (handle->error));
  handle->error[sizeof (handle->error) - 1] = '\0';
  free (s);

  if (VERBOSE (handle))
    puts (handle->error);

  va_end (ap);
}
